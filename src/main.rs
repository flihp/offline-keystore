// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use env_logger::Builder;
use log::{debug, error, info, LevelFilter};
use std::{
    env, io,
    path::{Path, PathBuf},
};
use yubihsm::object::{Id, Type};
use zeroize::Zeroizing;

use oks::{
    burner::{Burner, Cdr},
    config::{Transport, ENV_NEW_PASSWORD, ENV_PASSWORD},
    hsm::{Hsm, Shares, SHARES},
    shares::ShareMethod,
    storage::{Storage, DEFAULT_INPUT, DEFAULT_STATE, DEFAULT_VERIFIER},
};

const PASSWD_PROMPT: &str = "Enter new password: ";
const PASSWD_PROMPT2: &str = "Enter password again to confirm: ";

const GEN_PASSWD_LENGTH: usize = 16;

#[derive(ValueEnum, Clone, Debug, Default, PartialEq)]
enum AuthMethod {
    #[default]
    Cdrom,
    Password,
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
/// Create and restore split yubihsm wrap keys
struct Args {
    /// Increase verbosity
    #[clap(long, env)]
    verbose: bool,

    /// Directory where we put KeySpec, CA state and backups
    #[clap(long, env, default_value = DEFAULT_STATE)]
    state: PathBuf,

    /// 'usb' or 'http'
    #[clap(long, env, default_value = "usb")]
    transport: Transport,

    /// ID of authentication credential
    #[clap(long, env)]
    auth_id: Option<Id>,

    /// method used to get authentication value
    #[clap(long, env)]
    auth_method: Option<AuthMethod>,

    /// method used to get authentication value
    #[clap(long, env)]
    auth_dev: Option<PathBuf>,

    /// subcommands
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug, PartialEq)]
enum Command {
    Ca {
        #[command(subcommand)]
        command: CaCommand,
    },
    Hsm {
        /// Skip creation of a wrap key when initializing the HSM.
        #[clap(long, env)]
        no_backup: bool,

        #[command(subcommand)]
        command: HsmCommand,
    },
    /// Execute the OKS provisioning ceremony in a single command. This
    /// is equivalent to executing `hsm initialize`, `hsm generate`,
    /// `ca initialize`, and `ca sign`.
    Ceremony {
        #[clap(long, env, default_value = DEFAULT_INPUT)]
        csr_spec: PathBuf,

        #[clap(long, env, default_value = DEFAULT_INPUT)]
        key_spec: PathBuf,

        /// Path to the YubiHSM PKCS#11 module
        #[clap(
            long,
            env = "OKS_PKCS11_PATH",
            default_value = "/usr/lib/pkcs11/yubihsm_pkcs11.so"
        )]
        pkcs11_path: PathBuf,

        #[clap(long, env)]
        cdr_dev: Option<PathBuf>,

        #[clap(long, env)]
        /// Challenge the caller for a new password, don't generate a
        /// random one for them.
        passwd_challenge: bool,

        #[clap(long, env)]
        iso_only: bool,
    },
}

#[derive(Subcommand, Debug, PartialEq)]
/// Commands for operating on the CAs associated with keys in the HSM.
enum CaCommand {
    /// Initialize an OpenSSL CA for the given key.
    Initialize {
        /// Spec file describing the CA signing key
        #[clap(long, env, default_value = DEFAULT_INPUT)]
        key_spec: PathBuf,

        /// Path to the YubiHSM PKCS#11 module
        #[clap(
            long,
            env = "OKS_PKCS11_PATH",
            default_value = "/usr/lib/pkcs11/yubihsm_pkcs11.so"
        )]
        pkcs11_path: PathBuf,
    },

    /// Use the CA associated with the provided key spec to sign the
    /// provided CSR.
    Sign {
        #[clap(long, env, default_value = DEFAULT_INPUT)]
        csr_spec: PathBuf,
    },
}

#[derive(Subcommand, Clone, Debug, PartialEq)]
#[clap(verbatim_doc_comment)]
/// Commands for interacting with the YubiHSM2 during key ceremonies.
/// Behavior of this command is influenced by the following environment
/// variables:
/// - OKS_PASSWORD - if set this command will use the value from this
///   variable for authention with the HSM
/// - OKS_NEW_PASSWORD - if set this command will use the value from this
///   variable as the password for a newly created admin auth credential
enum HsmCommand {
    /// Generate keys in YubiHSM from specification.
    Generate {
        #[clap(long, env, default_value = DEFAULT_INPUT)]
        key_spec: PathBuf,
    },

    /// Initialize the YubiHSM for use in the OKS.
    Initialize {
        #[clap(long, env)]
        cdr_dev: Option<PathBuf>,

        #[clap(long, env)]
        /// Challenge the caller for a new password, don't generate a
        /// random one for them.
        passwd_challenge: bool,

        #[clap(long, env)]
        iso_only: bool,
    },

    /// Restore a previously split aes256-ccm-wrap key
    Restore {
        #[clap(long, env, default_value = DEFAULT_INPUT)]
        backups: PathBuf,

        #[clap(long, env, default_value = DEFAULT_VERIFIER)]
        verifier: PathBuf,

        #[clap(long, env)]
        /// Method used to collect shares of backup key
        share_method: Option<ShareMethod>,

        #[clap(long, env)]
        /// Path to device used to collect keyshares. If `--share-method` is
        /// `cdrom` then this is the path to the CD device. If
        /// `--share-method` is `iso` then `share-device` is the path to the
        /// directory where the share isos are stored. The names of these
        /// files must be the same as when created by oks.
        share_device: Option<PathBuf>,
    },

    /// Get serial number from YubiHSM and dump to console.
    SerialNumber,
}

/// Get password either from environment, the YubiHSM2 default, challenge
/// the user with a password prompt, or from the CDROM.
fn get_passwd<P: AsRef<Path>>(
    auth_method: Option<AuthMethod>,
    auth_dev: Option<P>,
) -> Result<Zeroizing<String>> {
    debug!("get_passwd");
    let auth_method = auth_method.unwrap_or(AuthMethod::Cdrom);
    match auth_method {
        AuthMethod::Cdrom => {
            let mut cdr = Cdr::new(auth_dev)?;
            cdr.mount()?;
            let passwd = cdr.read_password()?;
            cdr.teardown();
            Ok(passwd)
        }
        AuthMethod::Password => {
            debug!("AuthMethod::Passwd");

            let passwd = Zeroizing::new(match env::var(ENV_PASSWORD) {
                Ok(p) => p,
                Err(_) => {
                    rpassword::prompt_password("Enter YubiHSM Password: ")?
                }
            });

            Ok(passwd)
        }
    }
}

/// get a new password from the environment or by issuing a challenge the user
fn get_new_passwd(hsm: Option<&Hsm>) -> Result<Zeroizing<String>> {
    match env::var(ENV_NEW_PASSWORD).ok() {
        // prefer new password from env above all else
        Some(s) => {
            info!("got password from env");
            Ok(Zeroizing::new(s))
        }
        None => match hsm {
            // use the HSM otherwise if available
            Some(hsm) => {
                info!("Generating random password");
                Ok(Zeroizing::new(hsm.rand_string(GEN_PASSWD_LENGTH)?))
            }
            // last option: challenge the caller
            None => loop {
                let password =
                    Zeroizing::new(rpassword::prompt_password(PASSWD_PROMPT)?);
                let password2 =
                    Zeroizing::new(rpassword::prompt_password(PASSWD_PROMPT2)?);
                if password != password2 {
                    error!("the passwords entered do not match");
                } else {
                    debug!("got the same password twice");
                    return Ok(password);
                }
            },
        },
    }
}

/// Perform all operations that make up the ceremony for provisioning an
/// offline keystore.
// TODO: refactor
#[allow(clippy::too_many_arguments)]
fn do_ceremony(
    csr_spec: PathBuf,
    key_spec: PathBuf,
    pkcs11_path: PathBuf,
    cdr_dev: Option<PathBuf>,
    challenge: bool,
    iso_only: bool,
    state: &PathBuf,
    transport: Transport,
) -> Result<()> {
    let storage = Storage::new(Some(state));
    let passwd_new = {
        // assume YubiHSM is in default state: use default auth credentials
        let passwd = "password".to_string();
        let hsm = Hsm::new(1, &passwd, storage.clone(), true, transport)?;

        let shares = hsm.new_split_wrap()?;
        burn_shares(&shares, cdr_dev.clone(), iso_only)?;
        info!("Collecting YubiHSM attestation cert.");
        hsm.collect_attest_cert()?;

        let passwd = if challenge {
            get_new_passwd(None)?
        } else {
            get_new_passwd(Some(&hsm))?
        };
        burn_password(&passwd, cdr_dev, iso_only)?;
        hsm.replace_default_auth(&passwd)?;
        passwd
    };
    {
        // use new password to auth
        let hsm = Hsm::new(2, &passwd_new, storage.clone(), true, transport)?;
        hsm.generate(key_spec.as_ref())?;
    }
    // set env var for oks::ca module to pickup for PKCS11 auth
    env::set_var(ENV_PASSWORD, &passwd_new);
    oks::ca::initialize(
        key_spec.as_ref(),
        pkcs11_path.as_ref(),
        &storage.get_ca_root()?,
        &storage.get_output()?,
        transport,
    )?;
    oks::ca::sign(
        csr_spec.as_ref(),
        &storage.get_ca_root()?,
        &storage.get_output()?,
        transport,
    )
}

fn burn_shares(
    shares: &Shares,
    cdr_dev: Option<PathBuf>,
    iso_only: bool,
) -> Result<()> {
    println!(
        "\nThe wrap / backup key has been created and stored in the\n\
        YubiHSM. It will now be split into {} key shares and each share\n\
        will be written to separate CDs.\n\n",
        SHARES,
    );

    for (i, share) in shares.iter().enumerate() {
        let share_num = i + 1;
        debug!("witing keyshare {}: \"{:?}\"", share_num, share.as_ref());
        let burner = Burner::new(cdr_dev.clone())?;
        burner.write_share(share.as_ref())?;
        if !iso_only {
            burner.eject()?;
            println!(
                "Insert blank media into the CD writer & press enter to burn share[{}] ...",
                i + 1
            );
            wait_for_line()?;

            // error handling: be resilient to tray not closed?
            burner.burn()?;
            println!("Remove CD from drive then press enter.");
            wait_for_line()?;
        } else {
            // write ISOs to pwd
            burner.to_iso(format!("share_{}-of-{}.iso", share_num, SHARES))?;
        }
    }

    Ok(())
}

fn burn_password(
    password: &Zeroizing<String>,
    cdr_dev: Option<PathBuf>,
    iso_only: bool,
) -> Result<()> {
    let burner = Burner::new(cdr_dev)?;
    burner.write_password(password)?;
    if !iso_only {
        burner.eject()?;
        print!(
            "\nThe HSM authentication password has been created and stored in\n\
            the YubiHSM. It will now be written to CDR media. Insert a blank CD\n\
            into the drive and press enter to write auth value to CD ..."
        );
        wait_for_line()?;

        burner.burn()?;
        println!("Remove CD from drive then press enter.");
        wait_for_line()
    } else {
        // write to pwd
        burner.to_iso("password.iso")
    }
}

/// This function is used when displaying key shares as a way for the user to
/// control progression through the key shares displayed in the terminal.
fn wait_for_line() -> Result<()> {
    let _ = io::stdin().lines().next().unwrap()?;
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut builder = Builder::from_default_env();

    let level = if args.verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    builder.filter(None, level).init();

    let storage = Storage::new(Some(&args.state));
    match args.command {
        Command::Ca { command } => match command {
            CaCommand::Initialize {
                key_spec,
                pkcs11_path,
            } => oks::ca::initialize(
                &key_spec,
                &pkcs11_path,
                &storage.get_ca_root()?,
                &storage.get_output()?,
                args.transport,
            ),
            CaCommand::Sign { csr_spec } => oks::ca::sign(
                &csr_spec,
                &storage.get_ca_root()?,
                &storage.get_output()?,
                args.transport,
            ),
        },
        Command::Hsm { command, no_backup } => {
            let passwd = get_passwd(args.auth_method, args.auth_dev.as_ref())?;
            let auth_id = args.auth_id.unwrap_or(1);
            let hsm = Hsm::new(
                auth_id,
                &passwd,
                storage.clone(),
                !no_backup,
                args.transport,
            )?;

            match command {
                HsmCommand::Initialize {
                    cdr_dev,
                    passwd_challenge,
                    iso_only,
                } => {
                    debug!("Initialize");
                    if hsm.backup {
                        let shares = hsm.new_split_wrap()?;
                        burn_shares(&shares, cdr_dev.clone(), iso_only)?;
                    }
                    let passwd_new = if passwd_challenge {
                        get_new_passwd(None)?
                    } else {
                        get_new_passwd(Some(&hsm))?
                    };
                    burn_password(&passwd_new, cdr_dev, iso_only)?;
                    hsm.collect_attest_cert()?;
                    hsm.replace_default_auth(&passwd_new)
                }
                HsmCommand::Generate { key_spec } => hsm.generate(&key_spec),
                HsmCommand::Restore {
                    backups,
                    verifier,
                    share_method,
                    share_device,
                } => {
                    oks::hsm::reset(&hsm.client, false)?;
                    let hsm = Hsm::new(
                        1,
                        "password",
                        storage.clone(),
                        !no_backup,
                        args.transport,
                    )?;
                    hsm.collect_attest_cert()?;
                    hsm.restore_wrap(
                        verifier,
                        share_method.unwrap_or_else(ShareMethod::default),
                        share_device.unwrap_or_else(|| "/dev/cdrom".into()),
                    )?;
                    hsm.restore_all(backups)?;
                    info!("Deleting default authentication key");
                    oks::hsm::delete(&hsm.client, 1, Type::AuthenticationKey)
                }
                HsmCommand::SerialNumber => oks::hsm::dump_sn(&hsm.client),
            }
        }
        Command::Ceremony {
            ref csr_spec,
            ref key_spec,
            ref pkcs11_path,
            ref cdr_dev,
            passwd_challenge,
            iso_only,
        } => do_ceremony(
            csr_spec.clone(),
            key_spec.clone(),
            pkcs11_path.clone(),
            cdr_dev.clone(),
            passwd_challenge,
            iso_only,
            &args.state,
            args.transport,
        ),
    }
}
