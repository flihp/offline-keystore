// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result};
use log::{debug, error, info};
use p256::elliptic_curve::PrimeField;
use p256::{NonZeroScalar, ProjectivePoint, Scalar, SecretKey};
use pem_rfc7468::LineEnding;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use static_assertions as sa;
use std::collections::HashSet;
use std::{
    fs,
    io::{self, Read, Write},
    path::Path,
    str::FromStr,
};
use thiserror::Error;
use vsss_rs::{Feldman, FeldmanVerifier};
use yubihsm::{
    authentication::{self, Key, DEFAULT_AUTHENTICATION_KEY_ID},
    object::{Id, Label, Type},
    wrap::{self, Message},
    AuditOption, Capability, Client, Connector, Credentials, Domain,
    HttpConfig, UsbConfig,
};
use zeroize::Zeroizing;

use crate::{
    config::{self, KeySpec, Transport, BACKUP_EXT, KEYSPEC_EXT},
    storage::{Storage, VERIFIER_FILE_NAME},
};

const WRAP_ID: Id = 1;

const ALG: wrap::Algorithm = wrap::Algorithm::Aes256Ccm;
const CAPS: Capability = Capability::all();
const DELEGATED_CAPS: Capability = Capability::all();
const DOMAIN: Domain = Domain::all();
const ID: Id = 0x1;
const SEED_LEN: usize = 32;
const KEY_LEN: usize = 32;
const SHARE_LEN: usize = KEY_LEN + 1;
const LABEL: &str = "backup";

pub const SHARES: usize = 5;
const THRESHOLD: usize = 3;
sa::const_assert!(THRESHOLD <= SHARES);

const ATTEST_EXT: &str = ".attest.cert.pem";

pub type Share = vsss_rs::Share<SHARE_LEN>;
pub type Shares = [Share; SHARES];

#[derive(Error, Debug)]
pub enum HsmError {
    #[error("path not a directory")]
    BadSpecDirectory,
    #[error("failed conversion from YubiHSM Domain")]
    BadDomain,
    #[error("failed to convert use input into a key share")]
    BadKeyShare,
    #[error("failed conversion from YubiHSM Label")]
    BadLabel,
    #[error("Invalid purpose for root CA key")]
    BadPurpose,
    #[error("Combined shares produced an invalid Scalar")]
    BadScalar,
    #[error("Failed to combined shares into wrap key.")]
    CombineKeyFailed { e: vsss_rs::Error },
    #[error("Failed to split wrap key into shares.")]
    SplitKeyFailed { e: vsss_rs::Error },
    #[error("your yubihms is broke")]
    Version,
}

pub struct Alphabet {
    chars: Vec<char>,
}

impl Default for Alphabet {
    fn default() -> Self {
        Self::new()
    }
}

impl Alphabet {
    pub fn new() -> Self {
        let mut chars: HashSet<char> = HashSet::new();
        chars.extend('a'..='z');
        chars.extend('A'..='Z');
        chars.extend('0'..='9');

        // Remove visually similar characters
        chars = &chars - &HashSet::from(['l', 'I', '1']);
        chars = &chars - &HashSet::from(['B', '8']);
        chars = &chars - &HashSet::from(['O', '0']);

        // We generate random passwords from this alphabet by getting a byte
        // of random data from the HSM and using this value to pick
        // characters from the alphabet. Our alphabet cannot be larger than
        // the u8::MAX or it will ignore characters after the u8::MAXth.
        assert!(usize::from(u8::MAX) > chars.len());

        Alphabet {
            chars: chars.into_iter().collect(),
        }
    }

    pub fn get_char(&self, val: u8) -> Option<char> {
        let len = self.chars.len() as u8;
        // let rand = ;
        // Avoid biasing results by ensuring the random values we use
        // are a multiple of the length of the alphabet. If they aren't
        // we just get another.
        if val < u8::MAX - u8::MAX % len {
            Some(self.chars[(val % len) as usize])
        } else {
            None
        }
    }

    pub fn get_random_string(
        &self,
        get_rand_u8: impl Fn() -> Result<u8>,
        length: usize,
    ) -> Result<String> {
        let mut passwd = String::with_capacity(length + 1);

        for _ in 0..length {
            let char = loop {
                let rand = get_rand_u8()?;

                if let Some(char) = self.get_char(rand) {
                    break char;
                }
            };

            passwd.push(char);
        }

        Ok(passwd)
    }
}

/// Structure holding common data used by OKS when interacting with the HSM.
pub struct Hsm {
    pub client: Client,
    pub storage: Storage,
    pub alphabet: Alphabet,
    pub backup: bool,
}

impl Hsm {
    // 5 minute to support RSA4K key generation
    // NOTE: RSA key generation takes a lot of time on the YubiHSM. It's also
    // highly viariable: in practice we've seen RSA4K key generation take
    // anywhere from less than 1 minute to over 5 minutes.
    const TIMEOUT_MS: u64 = 300000;

    pub fn new(
        auth_id: Id,
        passwd: &str,
        storage: Storage,
        backup: bool,
        transport: Transport,
    ) -> Result<Self> {
        let connector = match transport {
            Transport::Usb => {
                let config = UsbConfig {
                    serial: None,
                    timeout_ms: Self::TIMEOUT_MS,
                };
                Connector::usb(&config)
            }
            Transport::Http => {
                let config = HttpConfig::default();
                Connector::http(&config)
            }
        };

        let credentials =
            Credentials::from_password(auth_id, passwd.as_bytes());
        let client = Client::open(connector, credentials, true)?;

        Ok(Hsm {
            client,
            storage,
            alphabet: Alphabet::new(),
            backup,
        })
    }

    pub fn rand_string(&self, length: usize) -> Result<String> {
        self.alphabet.get_random_string(
            || Ok(self.client.get_pseudo_random(1)?[0]),
            length,
        )
    }

    /// create a new wrap key, cut it up into shares, print those shares to
    /// `print_dev` & put the wrap key in the HSM
    pub fn new_split_wrap(&self) -> Result<Shares> {
        info!(
            "Generating wrap / backup key from HSM PRNG with label: \"{}\"",
            LABEL.to_string()
        );
        // get 32 bytes from YubiHSM PRNG
        // TODO: zeroize
        let wrap_key = self.client.get_pseudo_random(KEY_LEN)?;
        let rng_seed = self.client.get_pseudo_random(SEED_LEN)?;
        let rng_seed: [u8; SEED_LEN] =
            rng_seed.try_into().map_err(|v: Vec<u8>| {
                anyhow::anyhow!(
                    "Expected vec with {} elements, got {}",
                    SEED_LEN,
                    v.len()
                )
            })?;
        let mut rng = ChaCha20Rng::from_seed(rng_seed);

        info!("Splitting wrap key into {} shares.", SHARES);
        let wrap_key = SecretKey::from_be_bytes(&wrap_key)?;
        debug!("wrap key: {:?}", wrap_key.to_be_bytes());

        let nzs = wrap_key.to_nonzero_scalar();
        // we add a byte to the key length per instructions from the library:
        // https://docs.rs/vsss-rs/2.7.1/src/vsss_rs/lib.rs.html#34
        let (shares, verifier) = Feldman::<THRESHOLD, SHARES>::split_secret::<
            Scalar,
            ProjectivePoint,
            ChaCha20Rng,
            SHARE_LEN,
        >(*nzs.as_ref(), None, &mut rng)
        .map_err(|e| HsmError::SplitKeyFailed { e })?;

        let verifier = serde_json::to_string(&verifier)?;
        debug!("JSON: {}", verifier);
        self.storage
            .write_to_output(VERIFIER_FILE_NAME, verifier.as_bytes())?;

        // put 32 random bytes into the YubiHSM as an Aes256Ccm wrap key
        info!("Storing wrap key in YubiHSM.");
        let id = self.client
            .put_wrap_key::<[u8; 32]>(
                ID,
                Label::from_bytes(LABEL.as_bytes())?,
                DOMAIN,
                CAPS,
                DELEGATED_CAPS,
                ALG,
                wrap_key.to_be_bytes().into(),
            )
            .with_context(|| {
                format!(
                    "Failed to put wrap key into YubiHSM domains {:?} with id {}",
                    DOMAIN, ID
                )
            })?;
        debug!("wrap id: {}", id);
        // Future commands assume that our wrap key has id 1. If we got a wrap
        // key with any other id the HSM isn't in the state we think it is.
        assert_eq!(id, WRAP_ID);

        Ok(shares)
    }

    // create a new auth key, remove the default auth key, then export the new
    // auth key under the wrap key with the provided id
    // NOTE: This function consume self because it deletes the auth credential
    // that was used to create the client object. To use the HSM after calling
    // this function you'll need to reauthenticate.
    pub fn replace_default_auth(
        self,
        password: &Zeroizing<String>,
    ) -> Result<()> {
        info!("Setting up new auth credential.");
        // Key implements Zeroize internally on drop
        let auth_key = Key::derive_from_password(password.as_bytes());

        debug!("putting new auth key from provided password");
        // create a new auth key
        self.client.put_authentication_key(
            AUTH_ID,
            AUTH_LABEL.into(),
            AUTH_DOMAINS,
            AUTH_CAPS,
            AUTH_DELEGATED,
            authentication::Algorithm::default(), // can't be used in const
            auth_key,
        )?;

        if self.backup {
            info!("Backing up new auth credential.");
            self.backup_object(AUTH_ID, Type::AuthenticationKey)?;
        }

        info!("Deleting default auth key.");
        self.client.delete_object(
            DEFAULT_AUTHENTICATION_KEY_ID,
            Type::AuthenticationKey,
        )?;

        Ok(())
    }

    pub fn backup_object(&self, id: Id, kind: Type) -> Result<()> {
        info!("Backing up object with id: {:#06x} and type: {}", id, kind);
        let info = self.client.get_object_info(id, kind)?;
        info!("Backing up object with label: {}", info.label);
        let message = self.client.export_wrapped(WRAP_ID, kind, id)?;
        debug!("Got Message: {:?}", &message);

        let json = serde_json::to_string(&message)?;
        debug!("JSON: {}", json);

        let path = format!("{}.backup.json", info.label);
        info!("Writing backup to: \"{}\"", path);

        self.storage.write_to_output(&path, json.as_bytes())
    }

    pub fn generate(&self, key_spec: &Path) -> Result<()> {
        debug!("canonical KeySpec path: {}", key_spec.display());

        let paths = if key_spec.is_file() {
            vec![key_spec.to_path_buf()]
        } else {
            config::files_with_ext(key_spec, KEYSPEC_EXT)?
        };

        if paths.is_empty() {
            return Err(anyhow::anyhow!(
                "no files with extension \"{}\" found in dir: {}",
                KEYSPEC_EXT,
                &key_spec.display()
            ));
        }

        for path in paths {
            let json = fs::read_to_string(&path)?;
            debug!("spec as json: {}", json);

            let spec = KeySpec::from_str(&json)?;
            debug!("KeySpec from {}: {:#?}", path.display(), spec);

            info!("Generating key for spec: {:?}", path);
            let id = self.generate_keyspec(&spec)?;
            if self.backup {
                self.backup_object(id, Type::AsymmetricKey)?;
            }
        }

        Ok(())
    }

    /// Generate an asymmetric key from the provided specification.
    fn generate_keyspec(&self, spec: &KeySpec) -> Result<Id> {
        let id = self.client.generate_asymmetric_key(
            spec.id,
            spec.label.clone(),
            spec.domain,
            spec.capabilities,
            spec.algorithm,
        )?;
        debug!("new {:#?} key w/ id: {}", spec.algorithm, id);

        // get yubihsm attestation
        info!("Getting attestation for key with label: {}", spec.label);
        let attest_cert =
            self.client.sign_attestation_certificate(spec.id, None)?;

        let attest_cert = pem_rfc7468::encode_string(
            "CERTIFICATE",
            LineEnding::default(),
            attest_cert.as_slice(),
        )?;

        self.storage.write_to_output(
            &format!("{}.attest.cert.pem", spec.label),
            attest_cert.as_bytes(),
        )?;

        Ok(id)
    }

    /// This function prompts the user to enter M of the N backup shares. It
    /// uses these shares to reconstitute the wrap key. This wrap key can then
    /// be used to restore previously backed up / export wrapped keys.
    pub fn restore_wrap<P: AsRef<Path>>(&self, verifier: P) -> Result<()> {
        info!("Restoring HSM from backup");
        info!(
            "Restoring backup / wrap key from shares with verifier: {}",
            verifier.as_ref().display()
        );
        // vector used to collect shares
        let mut shares: Vec<Share> = Vec::new();

        // deserialize verifier:
        // verifier was serialized to output/verifier.json in the provisioning ceremony
        // it must be included in and deserialized from the ceremony inputs
        let verifier = fs::read_to_string(verifier)?;
        let verifier: FeldmanVerifier<Scalar, ProjectivePoint, SHARE_LEN> =
            serde_json::from_str(&verifier)?;

        // get enough shares to recover backup key
        for _ in 1..=THRESHOLD {
            // attempt to get a single share until the custodian enters a
            // share that we can verify
            loop {
                // clear the screen, move cursor to (0,0), & prompt user
                print!("\x1B[2J\x1B[1;1H");
                print!("Enter share\n: ");
                io::stdout().flush()?;
                // get share from stdin
                let mut share = String::new();
                let share = match io::stdin().read_line(&mut share) {
                    Ok(count) => match count {
                        0 => {
                            // Ctrl^D / EOF
                            continue;
                        }
                        // 33 bytes -> 66 characters + 1 newline
                        67 => share,
                        _ => {
                            print!(
                                "\nexpected 67 characters, got {}.\n\n\
                                Press any key to try again ...",
                                share.len()
                            );
                            io::stdout().flush()?;

                            // wait for a keypress / 1 byte from stdin
                            let _ = io::stdin().read(&mut [0u8]).unwrap();
                            continue;
                        }
                    },
                    Err(e) => {
                        print!(
                            "Error from `Stdin::read_line`: {}\n\n\
                            Press any key to try again ...",
                            e
                        );
                        io::stdout().flush()?;

                        // wait for a keypress / 1 byte from stdin
                        let _ = io::stdin().read(&mut [0u8]).unwrap();
                        continue;
                    }
                };

                // drop all whitespace from line entered, interpret it as a
                // hex string that we decode
                let share: String =
                    share.chars().filter(|c| !c.is_whitespace()).collect();
                let share_vec = match hex::decode(share) {
                    Ok(share) => share,
                    Err(_) => {
                        println!(
                            "Failed to decode Share. The value entered \
                                 isn't a valid hex string: try again."
                        );
                        continue;
                    }
                };

                // construct a Share from the decoded hex string
                let share: Share = match Share::try_from(&share_vec[..]) {
                    Ok(share) => share,
                    Err(_) => {
                        println!(
                            "Failed to convert share entered to Share \
                                type. The value entered is the wrong length \
                                ... try again."
                        );
                        continue;
                    }
                };

                if verifier.verify(&share) {
                    // if we're going to switch from paper to CDs for key
                    // share persistence this is the most obvious place to
                    // put a keyshare on to a CD w/ lots of refactoring
                    shares.push(share);
                    print!(
                        "\nShare verified!\n\nPress any key to continue ..."
                    );
                    io::stdout().flush()?;

                    // wait for a keypress / 1 byte from stdin
                    let _ = io::stdin().read(&mut [0u8]).unwrap();
                    break;
                } else {
                    print!(
                        "\nFailed to verify share :(\n\nPress any key to \
                        try again ..."
                    );
                    io::stdout().flush()?;

                    // wait for a keypress / 1 byte from stdin
                    let _ = io::stdin().read(&mut [0u8]).unwrap();
                    continue;
                }
            }
        }

        print!("\x1B[2J\x1B[1;1H");

        let scalar = Feldman::<THRESHOLD, SHARES>::combine_shares::<
            Scalar,
            SHARE_LEN,
        >(&shares)
        .map_err(|e| HsmError::CombineKeyFailed { e })?;

        let nz_scalar = NonZeroScalar::from_repr(scalar.to_repr());
        let nz_scalar = if nz_scalar.is_some().into() {
            nz_scalar.unwrap()
        } else {
            return Err(HsmError::BadScalar.into());
        };
        let wrap_key = SecretKey::from(nz_scalar);

        debug!("restored wrap key: {:?}", wrap_key.to_be_bytes());

        // put restored wrap key the YubiHSM as an Aes256Ccm wrap key
        let id = self.client
            .put_wrap_key::<[u8; KEY_LEN]>(
                ID,
                Label::from_bytes(LABEL.as_bytes())?,
                DOMAIN,
                CAPS,
                DELEGATED_CAPS,
                ALG,
                wrap_key.to_be_bytes().into(),
            )
            .with_context(|| {
                format!(
                    "Failed to put wrap key into YubiHSM domains {:?} with id {}",
                    DOMAIN, ID
                )
            })?;
        info!("wrap id: {}", id);

        Ok(())
    }

    pub fn restore_all<P: AsRef<Path>>(&self, backups: P) -> Result<()> {
        let backups = backups.as_ref();
        info!("Restoring from backups: \"{}\"", &backups.display());

        let backups = if backups.is_file() {
            vec![backups.to_path_buf()]
        } else {
            config::files_with_ext(backups, BACKUP_EXT)?
        };

        if backups.is_empty() {
            return Err(anyhow::anyhow!("no backups in provided directory"));
        }

        for backup in backups {
            info!("Restoring wrapped backup from file: {}", backup.display());
            let json = fs::read_to_string(backup)?;

            debug!("backup json: {}", json);
            let message: Message = serde_json::from_str(&json)?;

            debug!("deserialized message: {:?}", &message);
            let handle = self.client.import_wrapped(WRAP_ID, message)?;

            info!(
                "Imported {} key with object id {}.",
                handle.object_type, handle.object_id
            );
        }
        Ok(())
    }

    /// Write the cert for default attesation key in hsm to the provided
    /// filepath or a default location under self.output
    pub fn collect_attest_cert(&self) -> Result<()> {
        let sn = self.client.device_info()?.serial_number;
        info!("Collecting attestation cert for YubiHSM w/ SN: {}", sn);
        let attest_cert = self.client.get_opaque(0)?;

        let attest_cert = pem_rfc7468::encode_string(
            "CERTIFICATE",
            LineEnding::default(),
            &attest_cert,
        )?;

        let attest_path = format!("{}.{}", sn, ATTEST_EXT);
        debug!("writing attestation cert to: {}", attest_path);

        self.storage
            .write_to_output(&attest_path, attest_cert.as_bytes())
    }
}

pub fn delete(client: &Client, id: Id, kind: Type) -> Result<()> {
    info!("Deleting object with id: {} type: {}", &id, &kind);
    Ok(client.delete_object(id, kind)?)
}

pub fn dump_info(client: &Client) -> Result<()> {
    let info = client.device_info()?;
    println!("{:#?}", info);
    Ok(())
}

pub fn dump_sn(client: &Client) -> Result<()> {
    let info = client.device_info()?;
    println!("{}", info.serial_number);

    Ok(())
}

pub fn reset(client: &Client) -> Result<()> {
    let info = client.device_info()?;
    info!("resetting device with SN: {}", info.serial_number);

    if are_you_sure()? {
        client.reset_device()?;
        debug!("reset successful");
    } else {
        info!("reset aborted");
    }
    Ok(())
}

pub fn audit_lock(client: &Client) -> Result<()> {
    if are_you_sure()? {
        Ok(client.set_force_audit_option(AuditOption::Fix)?)
    } else {
        Err(anyhow::anyhow!("command aborted"))
    }
}

// consts for our authentication credential
const AUTH_DOMAINS: Domain = Domain::all();
const AUTH_CAPS: Capability = Capability::all();
const AUTH_DELEGATED: Capability = Capability::all();
const AUTH_ID: Id = 2;
const AUTH_LABEL: &str = "admin";

fn are_you_sure() -> Result<bool> {
    print!("Are you sure? (y/n):");
    io::stdout().flush()?;

    let mut buffer = String::new();
    io::stdin().read_line(&mut buffer)?;

    let buffer = buffer.trim().to_ascii_lowercase();
    debug!("got: \"{}\"", buffer);

    Ok(buffer == "y")
}

#[cfg(test)]
mod tests {
    use super::*;

    // secret split into the feldman verifier & shares below
    const SECRET: &str =
        "f259a45c17624b9317d8e292050c46a0f3d7387724b4cd26dd94f8bd3d1c0e1a";

    // verifier created and serialized to json by `new_split_wrap`
    const VERIFIER: &str = r#"
    {
        "generator": "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "commitments": [
            "02315e9e3cd76d0917ecd60378b75259bbdf2e35a31f46c05a497409d5d89c69dc",
            "0250e4e04d42e92bc15eecbe0789f5ac4831abe962df6b1eaed897e4634df702e3",
            "02dfc3c60074cb4896163e7e188f8ec93d3bd1e2fd2ed68854c9324e4a56e94cc7"
        ]
    }"#;

    // shares dumped to the printer by `new_split_wrap`
    const SHARE_ARRAY: [&str; SHARES] = [
        "01 b5b7dd6a 8ef8762f 0f266784 be191202 7b8a4b21 72fcb410 f28b2e1a e3669f9c",
        "02 042cfd2b 1ede9e78 d7827065 2d8c20ef 1cb43bf1 c722f2e3 a08ac387 b57b18f8",
        "03 ddb9039b c714c472 70ecfd33 53657366 51230043 6f56c6a8 cf074e89 ac1fc4d0",
        "04 425bf0bf 879ae818 db660def 2fa509f8 e221a80d 765153d1 a2d34dd7 d22d3321",
        "05 3215c494 6071096e 16eda298 c24ae4a6 497e28ab 2a41d768 036261f8 2063ae8d",
    ];

    fn secret_bytes() -> [u8; KEY_LEN] {
        let mut secret = [0u8; KEY_LEN];
        hex::decode_to_slice(SECRET, &mut secret).unwrap();

        secret
    }

    fn deserialize_share(share: &str) -> Result<Share> {
        // filter out whitespace to keep hex::decode happy
        let share: String =
            share.chars().filter(|c| !c.is_whitespace()).collect();
        let share = hex::decode(share)
            .context("failed to decode share from hex string")?;

        Ok(Share::try_from(&share[..])
            .context("Failed to construct Share from bytes.")?)
    }

    #[test]
    fn round_trip() -> Result<()> {
        use rand::rngs::ThreadRng;

        let secret = secret_bytes();
        let secret_key = SecretKey::from_be_bytes(&secret)?;
        let nzs = secret_key.to_nonzero_scalar();

        let mut rng = ThreadRng::default();
        let (shares, verifier) = Feldman::<THRESHOLD, SHARES>::split_secret::<
            Scalar,
            ProjectivePoint,
            ThreadRng,
            SHARE_LEN,
        >(*nzs.as_ref(), None, &mut rng)
        .map_err(|e| anyhow::anyhow!("failed to split secret: {}", e))?;

        for s in &shares {
            assert!(verifier.verify(s));
        }

        let scalar = Feldman::<THRESHOLD, SHARES>::combine_shares::<
            Scalar,
            SHARE_LEN,
        >(&shares)
        .map_err(|e| anyhow::anyhow!("failed to combine secret: {}", e))?;

        let nzs_dup = NonZeroScalar::from_repr(scalar.to_repr()).unwrap();
        let sk_dup = SecretKey::from(nzs_dup);
        let new_secret: [u8; KEY_LEN] = sk_dup.to_be_bytes().try_into()?;

        assert_eq!(new_secret, secret);

        Ok(())
    }

    // deserialize a verifier & use it to verify the shares in SHARE_ARRAY
    #[test]
    fn verify_shares() -> Result<()> {
        let verifier: FeldmanVerifier<Scalar, ProjectivePoint, SHARE_LEN> =
            serde_json::from_str(VERIFIER)
                .context("Failed to deserialize FeldmanVerifier from JSON.")?;

        for share in SHARE_ARRAY {
            let share = deserialize_share(share)?;
            assert!(verifier.verify(&share));
        }

        Ok(())
    }

    #[test]
    fn verify_zero_share() -> Result<()> {
        let verifier: FeldmanVerifier<Scalar, ProjectivePoint, SHARE_LEN> =
            serde_json::from_str(VERIFIER)
                .context("Failed to deserialize FeldmanVerifier from JSON.")?;

        let share: Share = Share::try_from([0u8; SHARE_LEN].as_ref())
            .context("Failed to create Share from static array.")?;

        assert!(!verifier.verify(&share));

        Ok(())
    }

    // TODO: I had expected that changing a single bit in a share would case
    // the verifier to fail but that seems to be very wrong.
    #[test]
    fn verify_share_with_changed_byte() -> Result<()> {
        let verifier: FeldmanVerifier<Scalar, ProjectivePoint, SHARE_LEN> =
            serde_json::from_str(VERIFIER)
                .context("Failed to deserialize FeldmanVerifier from JSON.")?;

        let mut share = deserialize_share(SHARE_ARRAY[0])?;
        println!("share: {}", share.0[0]);
        share.0[1] = 0xff;
        share.0[2] = 0xff;
        share.0[3] = 0xff;
        // If we don't change the next byte this test will start failing.
        // I had (wrongly?) expected that the share would fail to verify w/
        // a single changed byte
        share.0[4] = 0xff;

        assert!(!verifier.verify(&share));

        Ok(())
    }

    #[test]
    fn recover_secret() -> Result<()> {
        let mut shares: Vec<Share> = Vec::new();
        for share in SHARE_ARRAY {
            shares.push(deserialize_share(share)?);
        }

        let scalar = Feldman::<THRESHOLD, SHARES>::combine_shares::<
            Scalar,
            SHARE_LEN,
        >(&shares)
        .map_err(|e| anyhow::anyhow!("failed to combine secret: {}", e))?;

        let nzs_dup = NonZeroScalar::from_repr(scalar.to_repr()).unwrap();
        let sk_dup = SecretKey::from(nzs_dup);
        let secret: [u8; KEY_LEN] = sk_dup.to_be_bytes().try_into()?;

        assert_eq!(secret, secret_bytes());

        Ok(())
    }
}
