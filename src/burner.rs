// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result};
use log::{debug, warn};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
};
use tempfile::{tempdir, TempDir};
use thiserror::Error;

pub const DEFAULT_CDR_DEV: &str = "/dev/cdrom";

#[derive(Debug, Error)]
pub enum BurnerError {
    #[error("Source directory is neither a file nor a directory.")]
    BadSrc,

    #[error("Failed to burn tmpdir to CDR device.")]
    BurnFail,

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
            PathBuf::from_str(DEFAULT_CDR_DEV).expect("foo")
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

    pub fn write_to(&self, name: &str, data: &[u8]) -> Result<()> {
        debug!("Writing name: {} to: {}", name, self.tmp.as_ref().display());

        Ok(fs::write(self.tmp.as_ref().join(name), data)?)
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
}
