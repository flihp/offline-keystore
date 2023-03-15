// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result};
use fs_extra::dir::CopyOptions;
use hex::ToHex;
use log::{debug, error, info, warn};
use static_assertions as sa;
use std::{
    env,
    fs::{self, OpenOptions, Permissions},
    io::{self, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
    thread,
    time::Duration,
};
use tempfile::TempDir;
use thiserror::Error;
use yubihsm::{
    authentication::{self, Key, DEFAULT_AUTHENTICATION_KEY_ID},
    object::{Id, Label, Type},
    wrap, Capability, Client, Domain,
};
use zeroize::Zeroize;

pub mod config;

use config::{KeySpec, Purpose};

const ALG: wrap::Algorithm = wrap::Algorithm::Aes256Ccm;
const CAPS: Capability = Capability::all();
const DELEGATED_CAPS: Capability = Capability::all();
const DOMAIN: Domain = Domain::all();
const ID: Id = 0x1;
const KEY_LEN: usize = 32;
const LABEL: &str = "backup";

const SHARES: u8 = 5;
const THRESHOLD: u8 = 3;
sa::const_assert!(THRESHOLD <= SHARES);

const WRAP_ID: Id = 1;

/// Name of file in root of a CA directory with key spec used to generate key
/// in HSM.
const CA_KEY_SPEC: &str = "key.spec";

#[derive(Error, Debug)]
pub enum HsmError {
    #[error("path not a directory")]
    BadSpecDirectory,
    #[error("failed conversion from YubiHSM Domain")]
    BadDomain,
    #[error("failed conversion from YubiHSM Label")]
    BadLabel,
    #[error("Invalid purpose for root CA key")]
    BadPurpose,
    #[error("failed to generate certificate")]
    CertGenFail,
    #[error("failed to create self signed cert for key")]
    SelfCertGenFail,
    #[error("your yubihms is broke")]
    Version,
}

const PASSWD_PROMPT: &str = "Enter new HSM password: ";
const PASSWD_PROMPT2: &str = "Enter password again to confirm: ";

const KEYSPEC_EXT: &str = ".keyspec.json";
const CSRSPEC_EXT: &str = ".csrspec.json";

pub fn hsm_generate_key_batch(
    client: &Client,
    spec_dir: &Path,
    out_dir: &Path,
) -> Result<()> {
    info!("generating keys in batch mode from: {:?}", spec_dir);
    let mut paths: Vec<PathBuf> = Vec::new();
    for element in fs::read_dir(spec_dir)? {
        match element {
            Ok(e) => {
                let path = e.path();
                if path.to_string_lossy().ends_with(KEYSPEC_EXT) {
                    paths.push(path);
                }
            }
            Err(_) => continue,
        }
    }

    // no need for paths to be mutable past this point
    let paths = paths;
    for path in paths {
        info!("generating key for spec: {:?}", path);
        hsm_generate_key(client, &path, out_dir)?;
    }

    Ok(())
}

/// Generate an asymmetric key from the provided specification.
pub fn hsm_generate_key(
    client: &Client,
    key_spec: &Path,
    out_dir: &Path,
) -> Result<()> {
    let json = fs::read_to_string(key_spec)?;
    debug!("spec as json: {}", json);

    let spec = config::KeySpec::from_str(&json)?;
    debug!("KeySpec from {}: {:#?}", key_spec.display(), spec);

    let id = client.generate_asymmetric_key(
        spec.id,
        spec.label.clone(),
        spec.domain,
        spec.capabilities,
        spec.algorithm,
    )?;
    debug!("new {:#?} key w/ id: {}", spec.algorithm, id);

    debug!(
        "exporting new asymmetric key under wrap-key w/ id: {}",
        WRAP_ID
    );
    let msg = client.export_wrapped(WRAP_ID, Type::AsymmetricKey, id)?;
    let msg_json = serde_json::to_string(&msg)?;

    debug!("exported asymmetric key: {:#?}", msg_json);

    let mut out_pathbuf = out_dir.to_path_buf();
    out_pathbuf.push(format!("{}.wrap.json", spec.label));

    debug!("writing to: {}", out_pathbuf.display());
    fs::write(out_pathbuf, msg_json)?;

    // get yubihsm attestation
    info!("Getting attestation for key with label: {}", spec.label);
    let attest_cert = client.sign_attestation_certificate(spec.id, None)?;
    let attest_path = out_dir.join(format!("{}.attest.cert.pem", spec.label));
    fs::write(attest_path, attest_cert)?;

    Ok(())
}

// NOTE: before using the pkcs11 engine the connector must be running:
// sudo systemctl start yubihsm-connector
macro_rules! openssl_cnf_fmt {
    () => {
        r#"
openssl_conf                = default_modules

[default_modules]
engines                     = engine_section
oid_section                 = OIDs

[engine_section]
pkcs11                      = pkcs11_section

[pkcs11_section]
engine_id                   = pkcs11
MODULE_PATH                 = /usr/lib/pkcs11/yubihsm_pkcs11.so
INIT_ARGS                   = connector=http://127.0.0.1:12345 debug
init                        = 0

[ ca ]
default_ca                  = CA_default

[ CA_default ]
dir                         = ./
crl_dir                     = $dir/crl
database                    = $dir/index.txt
new_certs_dir               = $dir/newcerts
certificate                 = $dir/ca.cert.pem
serial                      = $dir/serial
# key format:   <slot>:<key id>
private_key                 = 0:{key:#04}
name_opt                    = ca_default
cert_opt                    = ca_default
# certs may be retired, but they won't expire
default_enddate             = 99991231235959Z
default_crl_days            = 30
default_md                  = {hash:?}
preserve                    = no
policy                      = policy_match
email_in_dn                 = no
rand_serial                 = no
unique_subject              = yes

[ policy_match ]
countryName                 = optional
stateOrProvinceName         = optional
organizationName            = optional
organizationalUnitName      = optional
commonName                  = supplied
emailAddress                = optional

[ req ]
default_md                  = {hash:?}
string_mask                 = utf8only

[ v3_code_signing_prod_ca ]
subjectKeyIdentifier        = hash
authorityKeyIdentifier      = keyid:always,issuer
basicConstraints            = critical,CA:true
keyUsage                    = critical, keyCertSign, cRLSign

[ v3_code_signing_prod ]
subjectKeyIdentifier        = hash
authorityKeyIdentifier      = keyid:always,issuer
basicConstraints            = critical,CA:false
keyUsage                    = critical, digitalSignature

[ v3_code_signing_dev_ca ]
subjectKeyIdentifier        = hash
authorityKeyIdentifier      = keyid:always,issuer
basicConstraints            = critical,CA:true
keyUsage                    = critical, keyCertSign, cRLSign
certificatePolicies         = critical,development-device-only

[ v3_code_signing_dev ]
subjectKeyIdentifier        = hash
authorityKeyIdentifier      = keyid:always,issuer
basicConstraints            = critical,CA:false
keyUsage                    = critical, digitalSignature
certificatePolicies         = critical,development-device-only

[ v3_identity ]
subjectKeyIdentifier        = hash
authorityKeyIdentifier      = keyid:always,issuer
basicConstraints            = critical,CA:true
keyUsage                    = critical, keyCertSign, cRLSign

[ OIDs ]
development-device-only = 1.3.6.1.4.1.57551.1
"#
    };
}

/// Get password for pkcs11 operations to keep the user from having to enter
/// the password multiple times (once for signing the CSR, one for signing
/// the cert). We also prefix the password with '0002' so the YubiHSM
/// PKCS#11 module knows which key to use
fn passwd_to_env(env_str: &str) -> Result<()> {
    let mut password = "0002".to_string();
    password.push_str(&rpassword::prompt_password("Enter YubiHSM Password: ")?);
    std::env::set_var(env_str, password);

    Ok(())
}

pub fn ca_initialize(
    key_spec: &Path,
    ca_state: &Path,
    out: &Path,
) -> Result<()> {
    let json = fs::read_to_string(key_spec)?;
    debug!("spec as json: {}", json);

    let spec = config::KeySpec::from_str(&json)?;
    debug!("KeySpec from {}: {:#?}", key_spec.display(), spec);

    // sanity check: no signing keys at CA init
    // this makes me think we need different types for this:
    // one for the CA keys, one for the children we sign
    match spec.purpose {
        Purpose::ProductionCodeSigningCA
        | Purpose::DevelopmentCodeSigningCA
        | Purpose::Identity => (),
        _ => return Err(HsmError::BadPurpose.into()),
    }

    passwd_to_env("OKM_HSM_PKCS11_AUTH")?;
    // check that password works before using it
    // doing this after we've already created a buch of directories will
    // leave us in an inconsistent state

    let pwd = std::env::current_dir()?;
    debug!("got current directory: {:?}", pwd);

    // setup CA directory structure
    let label = spec.label.to_string();
    let ca_dir = ca_state.join(&label);
    info!("bootstrapping CA files in: {}", ca_dir.display());
    fs::create_dir(&ca_dir)?;
    debug!("setting current directory: {}", ca_dir.display());
    std::env::set_current_dir(&ca_dir)?;

    // copy the key spec file to the ca state dir
    fs::write("key.spec", json)?;

    bootstrap_ca(&spec)?;

    debug!("starting connector");
    let mut connector = Command::new("yubihsm-connector").spawn()?;

    debug!("connector started");
    thread::sleep(Duration::from_millis(1000));

    // We're chdir-ing around and that makes it a PITA to keep track of file
    // paths. Stashing everything in a tempdir make it easier to copy it all
    // out when we're done.
    let tmp_dir = TempDir::new()?;
    let csr = tmp_dir.path().join(format!("{}.csr.pem", label));

    let mut cmd = Command::new("openssl");
    let output = cmd
        .arg("req")
        .arg("-config")
        .arg("openssl.cnf")
        .arg("-new")
        .arg("-subj")
        .arg(format!("/CN={}/", spec.common_name))
        .arg("-engine")
        .arg("pkcs11")
        .arg("-keyform")
        .arg("engine")
        .arg("-key")
        .arg(format!("0:{:#04}", spec.id))
        .arg("-passin")
        .arg("env:OKM_HSM_PKCS11_AUTH")
        .arg("-out")
        .arg(&csr)
        .output()?;

    info!("executing command: \"{:#?}\"", cmd);

    if !output.status.success() {
        warn!("command failed with status: {}", output.status);
        warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
        connector.kill()?;
        return Err(HsmError::SelfCertGenFail.into());
    }

    //  generate cert for CA root
    //  select v3 extensions from ... key spec?
    let mut cmd = Command::new("openssl");
    let output = cmd
        .arg("ca")
        .arg("-batch")
        .arg("-selfsign")
        .arg("-config")
        .arg("openssl.cnf")
        .arg("-engine")
        .arg("pkcs11")
        .arg("-keyform")
        .arg("engine")
        .arg("-keyfile")
        .arg(format!("0:{:#04}", spec.id))
        .arg("-extensions")
        .arg(spec.purpose.to_string())
        .arg("-passin")
        .arg("env:OKM_HSM_PKCS11_AUTH")
        .arg("-in")
        .arg(&csr)
        .arg("-out")
        .arg("ca.cert.pem")
        .output()?;

    info!("executing command: \"{:#?}\"", cmd);

    if !output.status.success() {
        warn!("command failed with status: {}", output.status);
        warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
        connector.kill()?;
        return Err(HsmError::SelfCertGenFail.into());
    }

    connector.kill()?;

    let cert = tmp_dir.path().join(format!("{}.cert.pem", label));
    fs::copy("ca.cert.pem", cert)?;

    env::set_current_dir(pwd)?;

    // copy contents of temp directory to out
    debug!("tmpdir: {:?}", tmp_dir);
    let paths = fs::read_dir(tmp_dir.path())?
        .map(|res| res.map(|e| e.path()))
        .collect::<Result<Vec<_>, io::Error>>()?;
    let opts = CopyOptions::default().overwrite(true);
    fs_extra::move_items(&paths, out, &opts)?;

    Ok(())
}

fn files_with_ext(dir: &Path, ext: &str) -> Result<Vec<PathBuf>> {
    if !dir.is_dir() {
        error!("not a directory: {}", dir.display());
        return Err(HsmError::BadSpecDirectory.into());
    }
    let mut paths: Vec<PathBuf> = Vec::new();
    for element in fs::read_dir(dir)? {
        match element {
            Ok(e) => {
                let path = e.path();
                if path.to_string_lossy().ends_with(ext) {
                    paths.push(path);
                }
            }
            Err(e) => {
                warn!("skipping directory entry due to error: {}", e);
                continue;
            }
        }
    }

    Ok(paths)
}

pub fn ca_sign(
    csr_spec_path: &Path,
    state: &Path,
    publish: &Path,
) -> Result<()> {
    let csr_spec_path = fs::canonicalize(csr_spec_path)?;
    debug!("canonical CsrSpec path: {}", csr_spec_path.display());

    let paths = if csr_spec_path.is_file() {
        vec![csr_spec_path]
    } else {
        files_with_ext(&csr_spec_path, CSRSPEC_EXT)?
    };

    // start connector
    debug!("starting connector");
    let mut connector = Command::new("yubihsm-connector").spawn()?;

    debug!("connector started");
    std::thread::sleep(std::time::Duration::from_millis(1000));

    passwd_to_env("OKM_HSM_PKCS11_AUTH")?;

    let tmp_dir = TempDir::new()?;
    for path in paths {
        // process csr spec
        info!("Signing CSR from spec: {:?}", path);
        if let Err(e) = ca_sign_csrspec(&path, &tmp_dir, state, publish) {
            // Ignore possible error from killing connector because we already
            // have an error to report and it'll be more interesting.
            let _ = connector.kill();
            return Err(e);
        }
    }

    // kill connector
    connector.kill()?;

    Ok(())
}

pub fn ca_sign_csrspec(
    csr_spec_path: &Path,
    tmp_dir: &TempDir,
    state: &Path,
    publish: &Path,
) -> Result<()> {
    // deserialize the csrspec
    debug!("Getting CSR spec from: {}", csr_spec_path.display());
    let json = fs::read_to_string(csr_spec_path)?;
    debug!("spec as json: {}", json);

    let csr_spec = config::CsrSpec::from_str(&json)?;
    debug!("CsrSpec: {:#?}", csr_spec);

    // get the label
    // use label to reconstruct path to CA root dir for key w/ label
    let key_spec = state.join(csr_spec.label.to_string()).join(CA_KEY_SPEC);

    debug!("Getting KeySpec from: {}", key_spec.display());
    let json = fs::read_to_string(key_spec)?;
    debug!("spec as json: {}", json);

    let key_spec = config::KeySpec::from_str(&json)?;
    debug!("KeySpec: {:#?}", key_spec);

    // sanity check: no signing keys at CA init
    // this makes me think we need different types for this:
    // one for the CA keys, one for the children we sign
    // map purpose of CA key to key associated with CSR
    let purpose = match key_spec.purpose {
        Purpose::ProductionCodeSigningCA => Purpose::ProductionCodeSigning,
        Purpose::DevelopmentCodeSigningCA => Purpose::DevelopmentCodeSigning,
        Purpose::Identity => Purpose::Identity,
        _ => return Err(HsmError::BadPurpose.into()),
    };

    let publish = fs::canonicalize(publish)?;
    debug!("canonical publish: {}", publish.display());

    // pushd into ca dir based on spec file
    let pwd = std::env::current_dir()?;
    debug!("got current directory: {:?}", pwd);

    let ca_dir = state.join(key_spec.label.to_string());
    std::env::set_current_dir(&ca_dir)?;
    debug!("setting current directory: {}", ca_dir.display());

    // Get prefix from CsrSpec file. We us this to generate file names for the
    // temp CSR file and the output cert file.
    let csr_filename = csr_spec_path
        .file_name()
        .unwrap()
        .to_os_string()
        .into_string()
        .unwrap();
    let csr_prefix = match csr_filename.find('.') {
        Some(i) => csr_filename[..i].to_string(),
        None => csr_filename,
    };

    // create a tempdir & write CSR there for openssl: AFAIK the `ca` command
    // won't take the CSR over stdin
    let tmp_csr = tmp_dir.path().join(format!("{}.csr.pem", csr_prefix));
    debug!("writing CSR to: {}", tmp_csr.display());
    fs::write(&tmp_csr, &csr_spec.csr)?;

    let cert = publish.join(format!("{}.cert.pem", csr_prefix));
    debug!("writing cert to: {}", cert.display());

    // execute CA command
    let mut cmd = Command::new("openssl");
    cmd.arg("ca")
        .arg("-batch")
        .arg("-config")
        .arg("openssl.cnf")
        .arg("-engine")
        .arg("pkcs11")
        .arg("-keyform")
        .arg("engine")
        .arg("-keyfile")
        .arg(format!("0:{:#04}", key_spec.id))
        .arg("-extensions")
        .arg(purpose.to_string())
        .arg("-passin")
        .arg("env:OKM_HSM_PKCS11_AUTH")
        .arg("-in")
        .arg(&tmp_csr)
        .arg("-out")
        .arg(&cert);

    info!("executing command: \"{:#?}\"", cmd);
    let output = cmd.output()?;

    if !output.status.success() {
        warn!("command failed with status: {}", output.status);
        warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
        return Err(HsmError::CertGenFail.into());
    }

    std::env::set_current_dir(pwd)?;

    Ok(())
}

/// Create the directory structure and initial files expected by the `openssl ca` tool.
fn bootstrap_ca(key_spec: &KeySpec) -> Result<()> {
    // create directories expected by `openssl ca`: crl, newcerts
    for dir in ["crl", "newcerts"] {
        debug!("creating directory: {}?", dir);
        fs::create_dir(dir)?;
    }

    // the 'private' directory is a special case w/ restricted permissions
    let priv_dir = "private";
    debug!("creating directory: {}?", priv_dir);
    fs::create_dir(priv_dir)?;
    let perms = Permissions::from_mode(0o700);
    debug!(
        "setting permissions on directory {} to {:#?}",
        priv_dir, perms
    );
    fs::set_permissions(priv_dir, perms)?;

    // touch 'index.txt' file
    let index = "index.txt";
    debug!("touching file {}", index);
    OpenOptions::new().create(true).write(true).open(index)?;

    // write initial serial number to 'serial' (echo 1000 > serial)
    let serial = "serial";
    let sn = 1000u32;
    debug!(
        "setting initial serial number to \"{}\" in file \"{}\"",
        sn, serial
    );
    fs::write(serial, sn.to_string())?;

    // create & write out an openssl.cnf
    fs::write(
        "openssl.cnf",
        format!(openssl_cnf_fmt!(), key = key_spec.id, hash = key_spec.hash),
    )?;

    Ok(())
}

/// This function prompts the user to enter M of the N backup shares. It
/// uses these shares to reconstitute the wrap key. This wrap key can then
/// be used to restore previously backed up / export wrapped keys.
pub fn restore(client: &Client) -> Result<()> {
    let mut shares: Vec<String> = Vec::new();

    for i in 1..=THRESHOLD {
        println!("Enter share[{}]: ", i);
        shares.push(io::stdin().lines().next().unwrap().unwrap());
    }

    for (i, share) in shares.iter().enumerate() {
        println!("share[{}]: {}", i, share);
    }

    let wrap_key =
        rusty_secrets::recover_secret(shares).unwrap_or_else(|err| {
            println!("Unable to recover key: {}", err);
            std::process::exit(1);
        });

    debug!("restored wrap key: {}", wrap_key.encode_hex::<String>());

    // put restored wrap key the YubiHSM as an Aes256Ccm wrap key
    let id = client
        .put_wrap_key(
            ID,
            Label::from_bytes(LABEL.as_bytes())?,
            DOMAIN,
            CAPS,
            DELEGATED_CAPS,
            ALG,
            wrap_key,
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

/// Initialize a new YubiHSM 2 by creating:
/// - a new wap key for backup
/// - a new auth key derived from a user supplied password
/// This new auth key is backed up / exported under wrap using the new wrap
/// key. This backup is written to the provided directory path. Finally this
/// function removes the default authentication credentials.
pub fn hsm_initialize(
    client: &Client,
    out_dir: &Path,
    print_dev: &Path,
) -> Result<()> {
    // get 32 bytes from YubiHSM PRNG
    // TODO: zeroize
    let wrap_key = client.get_pseudo_random(KEY_LEN)?;
    info!("got {} bytes from YubiHSM PRNG", KEY_LEN);
    debug!("got wrap key: {}", wrap_key.encode_hex::<String>());

    // put 32 random bytes into the YubiHSM as an Aes256Ccm wrap key
    let id = client
        .put_wrap_key::<Vec<u8>>(
            ID,
            Label::from_bytes(LABEL.as_bytes())?,
            DOMAIN,
            CAPS,
            DELEGATED_CAPS,
            ALG,
            wrap_key.clone(),
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

    // do the stuff from replace-auth.sh
    personalize(client, WRAP_ID, out_dir)?;

    let shares = rusty_secrets::generate_shares(THRESHOLD, SHARES, &wrap_key)
        .with_context(|| {
        format!(
            "Failed to split secret into {} shares with threashold {}",
            SHARES, THRESHOLD
        )
    })?;

    println!(
        "WARNING: The wrap / backup key has been created and stored in the\n\
        YubiHSM. It will now be split into {} key shares and each share\n\
        will be individually written to {}. Before each keyshare is\n\
        printed, the operator will be prompted to ensure the appropriate key\n\
        custodian is present in front of the printer.\n\n\
        Press enter to begin the key share recording process ...",
        SHARES,
        print_dev.display(),
    );

    wait_for_line();

    let mut print_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(print_dev)?;

    for (i, share) in shares.iter().enumerate() {
        let share_num = i + 1;
        println!(
            "When key custodian {num} is ready, press enter to print share \
            {num}",
            num = share_num,
        );
        wait_for_line();

        print_file.write_all(format!("{}\n", share).as_bytes())?;
        println!(
            "When key custodian {} has collected their key share, press enter",
            share_num,
        );
        wait_for_line();
    }

    Ok(())
}

// consts for our authentication credential
const AUTH_DOMAINS: Domain = Domain::all();
const AUTH_CAPS: Capability = Capability::all();
const AUTH_DELEGATED: Capability = Capability::all();
const AUTH_ID: Id = 2;
const AUTH_LABEL: &str = "admin";

// create a new auth key, remove the default auth key, then export the new
// auth key under the wrap key with the provided id
fn personalize(client: &Client, wrap_id: Id, out_dir: &Path) -> Result<()> {
    debug!(
        "personalizing with wrap key {} and out_dir {}",
        wrap_id,
        out_dir.display()
    );
    // get a new password from the user
    let mut password = loop {
        let password = rpassword::prompt_password(PASSWD_PROMPT).unwrap();
        let mut password2 = rpassword::prompt_password(PASSWD_PROMPT2).unwrap();
        if password != password2 {
            error!("the passwords entered do not match");
        } else {
            password2.zeroize();
            break password;
        }
    };
    debug!("got the same password twice: {}", password);

    // not compatible with Zeroizing wrapper
    let auth_key = Key::derive_from_password(password.as_bytes());

    debug!("putting new auth key from provided password");
    // create a new auth key
    client.put_authentication_key(
        AUTH_ID,
        AUTH_LABEL.into(),
        AUTH_DOMAINS,
        AUTH_CAPS,
        AUTH_DELEGATED,
        authentication::Algorithm::default(), // can't be used in const
        auth_key,
    )?;

    debug!("deleting default auth key");
    client.delete_object(
        DEFAULT_AUTHENTICATION_KEY_ID,
        Type::AuthenticationKey,
    )?;

    debug!("exporting new auth key under wrap-key w/ id: {}", wrap_id);
    let msg =
        client.export_wrapped(wrap_id, Type::AuthenticationKey, AUTH_ID)?;

    // include additional metadata (enough to reconstruct current state)?
    let msg_json = serde_json::to_string(&msg)?;

    debug!("msg_json: {:#?}", msg_json);

    // we need to append a name for our file
    let mut auth_wrap_path = out_dir.to_path_buf();
    auth_wrap_path.push(format!("{}.wrap.json", AUTH_LABEL));
    debug!("writing to: {}", auth_wrap_path.display());
    fs::write(&auth_wrap_path, msg_json)?;

    // dump cert for default attesation key in hsm
    debug!("extracting attestation certificate");
    let attest_cert = client.get_opaque(0)?;
    let mut attest_path = out_dir.to_path_buf();
    attest_path.push("hsm.attest.cert.pem");

    debug!("writing attestation cert to: {}", attest_path.display());
    fs::write(&attest_path, attest_cert)?;

    password.zeroize();

    Ok(())
}

/// This function is used when displaying key shares as a way for the user to
/// control progression through the key shares displayed in the terminal.
fn wait_for_line() {
    let _ = io::stdin().lines().next().unwrap().unwrap();
}
