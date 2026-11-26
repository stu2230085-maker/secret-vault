use std::{
    fs::{self, OpenOptions},
    io::{Seek, SeekFrom, Write},
    path::Path,
};

use rand::{RngCore, rngs::OsRng};

use super::format::{HEADER_LEN, SLOT_COUNT, SLOT_LEN};

pub(super) fn shred(path: &Path) -> std::io::Result<()> {
    let mut file = OpenOptions::new().write(true).open(path)?;
    let mut remaining = HEADER_LEN + SLOT_COUNT * SLOT_LEN;
    let mut random = [0; 4096];
    file.seek(SeekFrom::Start(0))?;
    while remaining > 0 {
        let length = remaining.min(random.len());
        OsRng.fill_bytes(&mut random[..length]);
        file.write_all(&random[..length])?;
        remaining -= length;
    }
    file.sync_all()?;
    drop(file);
    fs::remove_file(path)
}
