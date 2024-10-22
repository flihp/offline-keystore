// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::ValueEnum;
use glob::Paths;
use log::debug;
use p256::{ProjectivePoint, Scalar};
use std::{
    env,
    io::{self, Read, Write},
    ops::Deref,
    path::{Path, PathBuf},
};
use vsss_rs::FeldmanVerifier;
use zeroize::Zeroizing;

use crate::{
    burner::Cdr,
    hsm::{Share, SHARE_LEN},
};

pub type Verifier = FeldmanVerifier<Scalar, ProjectivePoint, SHARE_LEN>;

#[derive(ValueEnum, Clone, Debug, Default, PartialEq)]
pub enum ShareMethod {
    #[default]
    Cdrom,
    Iso,
    Stdin,
}

pub struct IsoShares {
    directory: PathBuf,
    share_glob: Option<Paths>,
    verifier: Verifier,
}

impl IsoShares {
    pub fn new<P: AsRef<Path>>(
        verifier: Verifier,
        directory: Option<P>,
    ) -> Result<Self> {
        let current_dir = env::current_dir()?;
        let directory = match directory {
            Some(d) => PathBuf::from(d.as_ref()),
            None => current_dir,
        };

        Ok(IsoShares {
            directory,
            share_glob: None,
            verifier,
        })
    }
}

impl Iterator for IsoShares {
    type Item = Result<Zeroizing<Share>>;

    fn next(&mut self) -> Option<Self::Item> {
        debug!("getting shares from ISOs in {}", self.directory.display());

        if self.share_glob.is_none() {
            let path = self.directory.join("share_*-of-*.iso");
            let path = path.to_str().unwrap();
            let glob = match glob::glob(path) {
                Ok(paths) => paths,
                Err(e) => return Some(Err(e.into())),
            };
            self.share_glob = Some(glob);
        }

        let share_glob = match self
            .share_glob
            .as_mut()
            .ok_or(anyhow::anyhow!("this shouldn't happen"))
        {
            Ok(paths) => paths,
            Err(e) => return Some(Err(e)),
        };

        let share_iso = match share_glob.next() {
            Some(r) => match r {
                Ok(iso) => iso,
                Err(e) => return Some(Err(e.into())),
            },
            None => return None,
        };

        let mut cdr = match Cdr::new(Some(share_iso)) {
            Ok(cdr) => cdr,
            Err(e) => return Some(Err(e)),
        };
        match cdr.mount() {
            Ok(()) => (),
            Err(e) => return Some(Err(e)),
        };
        let share = match cdr.read_share() {
            Ok(share) => share,
            Err(e) => return Some(Err(e)),
        };

        match verify(&self.verifier, &share) {
            Ok(b) => {
                if b {
                    Some(Ok(share))
                } else {
                    Some(Err(anyhow::anyhow!("verification failed")))
                }
            }
            Err(e) => Some(Err(e)),
        }
    }
}

pub struct CdrShares {
    device: Option<PathBuf>,
    verifier: Verifier,
}

impl CdrShares {
    pub fn new<P: AsRef<Path>>(verifier: Verifier, device: Option<P>) -> Self {
        let device = device.map(|p| PathBuf::from(p.as_ref()));
        Self { device, verifier }
    }
}

impl Iterator for CdrShares {
    type Item = Result<Zeroizing<Share>>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut cdr = match Cdr::new(self.device.as_ref()) {
            Ok(cdr) => cdr,
            Err(e) => return Some(Err(e)),
        };

        match cdr.eject() {
            Ok(()) => (),
            Err(e) => return Some(Err(e)),
        }

        print!(
            "Place keyshare CD in the drive, close the drive, then press \n\
               any key to continue: "
        );
        match io::stdout().flush() {
            Ok(()) => (),
            Err(e) => return Some(Err(e.into())),
        }
        // wait for user input
        let _ = io::stdin().read(&mut [0u8]).unwrap();

        // TODO: retry loop
        match cdr.mount() {
            Ok(()) => (),
            Err(e) => return Some(Err(e)),
        }
        let share = match cdr.read_share() {
            Ok(share) => share,
            Err(e) => return Some(Err(e)),
        };
        println!("\nOK");

        match verify(&self.verifier, &share) {
            Ok(b) => {
                if b {
                    Some(Ok(share))
                } else {
                    Some(Err(anyhow::anyhow!("verification failed")))
                }
            }
            Err(e) => Some(Err(e)),
        }
    }
}

pub struct TermShares {
    verifier: Verifier,
}

impl TermShares {
    pub fn new(verifier: Verifier) -> Self {
        Self { verifier }
    }
}

impl Iterator for TermShares {
    type Item = Result<Zeroizing<Share>>;

    fn next(&mut self) -> Option<Self::Item> {
        // get share from stdin
        loop {
            // clear the screen, move cursor to (0,0), & prompt user
            print!("\x1B[2J\x1B[1;1H");
            print!("Enter share\n: ");
            match io::stdout().flush() {
                Ok(()) => (),
                Err(e) => return Some(Err(e.into())),
            }

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
                        match io::stdout().flush() {
                            Ok(()) => (),
                            Err(e) => return Some(Err(e.into())),
                        }

                        // wait for a keypress / 1 byte from stdin
                        match io::stdin().read_exact(&mut [0u8]) {
                            Ok(_) => (),
                            Err(e) => return Some(Err(e.into())),
                        };
                        continue;
                    }
                },
                Err(e) => {
                    print!(
                        "Error from `Stdin::read_line`: {}\n\n\
                        Press any key to try again ...",
                        e
                    );
                    match io::stdout().flush() {
                        Ok(_) => (),
                        Err(e) => return Some(Err(e.into())),
                    }

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
            let share = match Share::try_from(&share_vec[..]) {
                Ok(share) => Zeroizing::new(share),
                Err(_) => {
                    println!(
                        "Failed to convert share entered to the Share type.\n\
                        The value entered is the wrong length ... try again."
                    );
                    continue;
                }
            };

            let verified = match verify(&self.verifier, &share) {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };

            if verified {
                break Some(Ok(share));
            }
        }
    }
}

fn verify(verifier: &Verifier, share: &Zeroizing<Share>) -> Result<bool> {
    if verifier.verify(share.deref()) {
        print!("\nShare verified!\n\nPress any key to continue ...");
        io::stdout().flush()?;

        // wait for a keypress / 1 byte from stdin
        let _ = io::stdin().read(&mut [0u8]).unwrap();
        print!("\x1B[2J\x1B[1;1H");
        Ok(true)
    } else {
        print!(
            "\nFailed to verify share :(\n\nPress any key to \
            try again ..."
        );
        io::stdout().flush()?;

        // wait for a keypress / 1 byte from stdin
        let _ = io::stdin().read(&mut [0u8]).unwrap();
        Ok(false)
    }
}
