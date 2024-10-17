// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result};
use log::{debug, warn};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::{tempdir, TempDir};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::hsm::Share;

pub const DEFAULT_CDR_DEV: &str = "/dev/cdrom";

#[derive(Debug, Error)]
pub enum CdrError {
    #[error("The device provided isn't a block dev or a regular file.")]
    BadDevice,

    #[error("Unable to get next available loopback device.")]
    GetLoopback,

    #[error("Failed to mount Cdr.")]
    MountFail,

    #[error("Failed to eject Cdr.")]
    EjectFail,
}

pub struct Cdr {
    device: PathBuf,
    tmpdir: TempDir,
    loopback: Option<PathBuf>,
}

impl Cdr {
    pub fn new<P: AsRef<Path>>(device: Option<P>) -> Result<Self> {
        let device = match device {
            Some(s) => PathBuf::from(s.as_ref()),
            None => PathBuf::from(DEFAULT_CDR_DEV),
        };
        Ok(Self {
            device,
            tmpdir: tempdir()?,
            loopback: None,
        })
    }

    pub fn eject(&self) -> Result<()> {
        let mut cmd = Command::new("eject");
        let output = cmd.arg(&self.device).output().with_context(|| {
            format!("failed to run the \"eject\" command: \"{:?}\"", cmd)
        })?;

        if !output.status.success() {
            warn!("command failed with status: {}", output.status);
            warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
            return Err(CdrError::EjectFail.into());
        }

        Ok(())
    }

    pub fn mount(&mut self) -> Result<()> {
        use std::os::unix::fs::FileTypeExt;
        // if self.device is a regular file assume it's an iso ... check
        // suffix too?
        // else if it's a device then just mount it
        // otherwise fail
        let file_type = self.device.metadata()?.file_type();
        if file_type.is_file() {
            // if we've been givn an ISO we need to setup a loopback device
            // checkout udisksctl?
            let mut cmd = Command::new("losetup");
            let output = cmd
                .arg("-f")
                .output()
                .with_context(|| "unable to execute \"losetup\"")?;

            debug!("executing command: \"{:#?}\"", cmd);

            if !output.status.success() {
                warn!("command failed with status: {}", output.status);
                warn!(
                    "stderr: \"{}\"",
                    String::from_utf8_lossy(&output.stderr)
                );
                return Err(CdrError::GetLoopback.into());
            }
            // get path to the loopback device from `losetup` stdout
            let loop_dev =
                String::from(String::from_utf8(output.stdout)?.trim());
            debug!("got loopback device: {}", loop_dev);
            let loop_dev = PathBuf::from(loop_dev);

            let mut cmd = Command::new("losetup");
            let output = cmd
                .arg(&loop_dev)
                .arg(&self.device)
                .output()
                .with_context(|| "failed to execute \"losetup\"")?;

            debug!("executing command: \"{:#?}\"", cmd);
            if !output.status.success() {
                warn!("command failed with status: {}", output.status);
                warn!(
                    "stderr: \"{}\"",
                    String::from_utf8_lossy(&output.stderr)
                );
                return Err(CdrError::GetLoopback.into());
            }

            self._mount(&loop_dev)?;
            self.loopback = Some(loop_dev);
        } else if file_type.is_block_device() {
            self._mount(&self.device)?;
        } else {
            return Err(CdrError::BadDevice.into());
        }
        Ok(())
    }

    pub fn read_password(&self) -> Result<Zeroizing<String>> {
        let path = self.tmpdir.as_ref().join("password");
        let passwd =
            Zeroizing::new(fs::read_to_string(&path).with_context(|| {
                format!("failed to read from file: {}", path.display())
            })?);
        debug!(
            "read password from {}: {}",
            self.tmpdir.as_ref().display(),
            <Zeroizing<String> as AsRef<str>>::as_ref(&passwd),
        );

        Ok(passwd)
    }

    pub fn read_share(&self) -> Result<Share> {
        let path = self.tmpdir.as_ref().join("share");
        let share = fs::read(&path).with_context(|| {
            format!("failed to read from file: {}", path.display())
        })?;
        let share = Share::try_from(share.as_ref()).with_context(|| {
            "data read from cdrom can't be converted to a Share"
        })?;
        Ok(share)
    }

    fn _mount<P: AsRef<Path>>(&self, device: &P) -> Result<()> {
        let mut cmd = Command::new("mount");
        let output = cmd
            .arg(device.as_ref())
            .arg(self.tmpdir.as_ref())
            .output()
            .with_context(|| {
                format!(
                    "failed to mount \"{}\" at \"{}\"",
                    device.as_ref().display(),
                    self.tmpdir.as_ref().display()
                )
            })?;

        if !output.status.success() {
            warn!("command failed with status: {}", output.status);
            warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
            return Err(CdrError::MountFail.into());
        }

        Ok(())
    }

    // do this in `Drop`?
    pub fn teardown(self) {
        // unmount self.tmpdir
        let mut cmd = Command::new("umount");
        let output = cmd.arg(self.device).arg(self.tmpdir.as_ref()).output();
        let output = match output {
            Ok(o) => o,
            _ => {
                warn!(
                    "failed to unmount \"{}\"",
                    self.tmpdir.as_ref().display()
                );
                return;
            }
        };

        if !output.status.success() {
            warn!("command failed with status: {}", output.status);
            warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
            return;
        }
        if self.loopback.is_some() {
            let loopback = self.loopback.unwrap();
            let mut cmd = Command::new("losetup");
            let output = cmd.arg("-d").arg(&loopback).output();

            let output = match output {
                Ok(o) => o,
                _ => {
                    warn!(
                        "failed to destroy loopback device {}",
                        loopback.display()
                    );
                    return;
                }
            };
            if !output.status.success() {
                warn!("command failed with status: {}", output.status);
                warn!(
                    "stderr: \"{}\"",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum BurnerError {
    #[error("Source directory is neither a file nor a directory.")]
    BadSrc,

    #[error("Failed to burn tmpdir to CDR device.")]
    BurnFail,

    #[error("Failed to eject tray from CDR device.")]
    EjectFail,

    #[error("Failed to make ISO from state directory.")]
    IsoFail,
}

pub struct Burner {
    tmp: TempDir,
    device: PathBuf,
}

impl Burner {
    // If `device` is `None` then we will only create an iso and return the
    // bytes.
    pub fn new(device: Option<PathBuf>) -> Result<Burner> {
        let device = device.unwrap_or_else(|| {
            // the error type return is infallible
            PathBuf::from(DEFAULT_CDR_DEV)
        });
        Ok(Self {
            device,
            tmp: tempdir()?,
        })
    }

    pub fn add<P: AsRef<Path>>(&self, src: &P) -> Result<()> {
        let name = src.as_ref().file_name().ok_or(BurnerError::BadSrc)?;
        let dst = self.tmp.path().join(name);

        let _ = fs::copy(src, &dst).context(format!(
            "Failed to copy source \"{}\" to destination \"{}\"",
            src.as_ref().display(),
            dst.display()
        ))?;
        Ok(())
    }

    pub fn write_password(&self, data: &Zeroizing<String>) -> Result<()> {
        let path = self.tmp.as_ref().join("password");
        debug!(
            "Writing password: {} to: {}",
            <Zeroizing<String> as AsRef<str>>::as_ref(data),
            path.display()
        );

        Ok(fs::write(path, data)?)
    }

    pub fn write_share(&self, data: &[u8]) -> Result<()> {
        let path = self.tmp.as_ref().join("share");
        debug!("Writing share: {:?} to: {}", data, path.display());

        Ok(fs::write(path, data)?)
    }

    pub fn to_iso<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut cmd = Command::new("mkisofs");
        let output = cmd
            .arg("-r")
            .arg("-iso-level")
            .arg("4")
            .arg("-o")
            .arg(path.as_ref())
            .arg(self.tmp.as_ref())
            .output()
            .with_context(|| {
                format!(
                    "failed to create state ISO at \"{}\"",
                    self.tmp.as_ref().display()
                )
            })?;

        if !output.status.success() {
            warn!("command failed with status: {}", output.status);
            warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
            return Err(BurnerError::IsoFail.into());
        }

        Ok(())
    }

    /// Burn data to CD & eject disk when done.
    pub fn burn(self) -> Result<()> {
        use tempfile::NamedTempFile;

        let iso = NamedTempFile::new()?;
        self.to_iso(iso)?;

        let mut cmd = Command::new("cdrecord");
        let output = cmd
            .arg("-eject")
            .arg("-data")
            .arg(self.tmp.as_ref())
            .arg("gracetime=0")
            .arg("timeout=1000")
            .arg(format!("dev={}", self.device.display()))
            .output()
            .with_context(|| {
                format!(
                    "failed to create ISO from \"{}\" at \"{}\"",
                    self.tmp.as_ref().display(),
                    self.tmp.as_ref().display()
                )
            })?;

        if !output.status.success() {
            warn!("command failed with status: {}", output.status);
            warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
            return Err(BurnerError::BurnFail.into());
        }

        Ok(())
    }

    /// Eject / open CD device.
    pub fn eject(&self) -> Result<()> {
        let mut cmd = Command::new("eject");
        let output = cmd.arg(&self.device).output().with_context(|| {
            format!("failed to eject CD device \"{}\"", self.device.display())
        })?;

        if !output.status.success() {
            warn!("command failed with status: {}", output.status);
            warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
            return Err(BurnerError::EjectFail.into());
        }

        Ok(())
    }
}
