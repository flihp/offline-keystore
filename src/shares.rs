// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::ValueEnum;
use p256::{ProjectivePoint, Scalar};
use std::{
    env,
    fs::ReadDir,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
use vsss_rs::FeldmanVerifier;

use crate::{
    burner::DEFAULT_CDR_DEV,
    hsm::{Share, SHARE_LEN},
};

type Verifier = FeldmanVerifier<Scalar, ProjectivePoint, SHARE_LEN>;

#[derive(ValueEnum, Clone, Debug, Default, PartialEq)]
pub enum ShareMethod {
    #[default]
    Cdrom,
    Iso,
    Stdin,
}

// if share_method is `Cdrom`
// - for i in THRESHOLD
//   - prompt for share in cd drive
//   - read share from device
//   - verify share (maybe)
//if share_method is `Iso`
// - for i in THRESHOLD
//   - if share_method is `Cdrom`
//     - prompt for share in cd drive & wait for key press
//   - if share_method is `Iso`
//     - get one share from share_dir
//   - read share from device
//   - verify share
// - create Cdr
// find the shares in `share_device`
/// A type to handle all of the details associated with getting shares into
/// OKS for recovering backups.
/// The structure here is a guess and will likely change to form itself around
/// the mechanics that we're currently trying to figure out here.
pub struct ShareGetter {
    share_method: ShareMethod,
    share_device: Option<PathBuf>,
    share_dir: Option<ReadDir>,
    verifier: Verifier,
}

impl ShareGetter {
    pub fn new<P: AsRef<Path>>(
        share_method: ShareMethod,
        share_device: Option<P>,
        verifier: Verifier,
    ) -> Result<Self> {
        // probably a candidate for a trait, builder and a concrete type
        // for each ShareMethod
        Ok(match share_method {
            ShareMethod::Cdrom => {
                let share_device = Some(match share_device {
                    Some(s) => PathBuf::from(s.as_ref()),
                    None => PathBuf::from(DEFAULT_CDR_DEV),
                });
                Self {
                    share_method,
                    share_device,
                    share_dir: None,
                    verifier,
                }
            }
            ShareMethod::Iso => {
                let current_dir = env::current_dir()?;
                let share_device = Some(match share_device {
                    Some(d) => PathBuf::from(d.as_ref()),
                    None => current_dir,
                });
                Self {
                    share_method,
                    share_device,
                    share_dir: None,
                    verifier,
                }
            }
            ShareMethod::Stdin => Self {
                share_method,
                share_device: None,
                share_dir: None,
                verifier,
            },
        })
    }

    // get one share via using the provided `ShareMethod`
    // returns Some(Share) until all available shares have been got
    //   NOTE: this type should probably not know about the threshold, only
    //   the limit
    // may make sense to add the verifier here so we can filter out / handle
    //   invalid shares ... seems like an error would work
    // basically an iterator
    // TODO: return Result<Option<Zeroizing<Share>>>
    pub fn get_share(&self) -> Result<Option<Share>> {
        match self.share_method {
            ShareMethod::Cdrom => self._get_cdrom_share(),
            ShareMethod::Iso => self._get_iso_share(),
            ShareMethod::Stdin => self._get_stdin_share(),
        }
    }

    fn _get_cdrom_share(&self) -> Result<Option<Share>> {
        todo!("ShareGetter::_get_cdrom_share");
    }

    fn _get_iso_share(&self) -> Result<Option<Share>> {
        todo!("ShareGetter::_get_iso_share");
    }

    /// Loop prompting the user to enter a keyshare & getting input from them
    /// until we get get something that we can construct a Share from. We
    /// don't verify the share, but we do ensure it's the correct size and
    /// valid hex.
    /// There's no logical upper bound on the number of times a user will need
    /// to enter shares since it's so error prone. Calling this function will
    /// never return None.
    fn _get_stdin_share(&self) -> Result<Option<Share>> {
        // get share from stdin
        loop {
            // clear the screen, move cursor to (0,0), & prompt user
            print!("\x1B[2J\x1B[1;1H");
            print!("Enter share\n: ");
            io::stdout().flush()?;

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
            let share = match Share::try_from(&share_vec[..]) {
                Ok(share) => share,
                Err(_) => {
                    println!(
                        "Failed to convert share entered to the Share type.\n\
                        The value entered is the wrong length ... try again."
                    );
                    continue;
                }
            };

            if self.verifier.verify(&share) {
                print!("\nShare verified!\n\nPress any key to continue ...");
                io::stdout().flush()?;

                // wait for a keypress / 1 byte from stdin
                let _ = io::stdin().read(&mut [0u8]).unwrap();
                print!("\x1B[2J\x1B[1;1H");
                break Ok(Some(share));
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
}
