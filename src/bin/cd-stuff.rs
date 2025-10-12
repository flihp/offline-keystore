// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Context;
use std::{
    fs::File,
    io::{self, Read, Write},
    ops::Deref,
    path::PathBuf,
};

use oks::cdrw::CdReader;
use oks::secret_reader::{CdrPasswordReader, PasswordReader};

fn main() -> anyhow::Result<()> {
    let reader = CdReader::new::<PathBuf>(None)?;
    if reader.is_cd_present()? {
        println!("cd is present");
    } else {
        println!("cd is *NOT* present");
    }

    let mut reader = CdrPasswordReader::new(reader);
    let passwd = reader.read("foo")?;

    println!("read password: {}", passwd.deref());

    Ok(())
}
