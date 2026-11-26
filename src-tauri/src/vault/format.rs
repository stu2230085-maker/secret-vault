use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use super::{crypto, shred};

pub(super) const HEADER_LEN: usize = 8;
pub(super) const SLOT_COUNT: usize = 4;
const SLOT_SALT_LEN: usize = 16;
const SLOT_NONCE_LEN: usize = 12;
const SLOT_TAG_LEN: usize = 16;
pub(super) const SLOT_CIPHERTEXT_LEN: usize = 34 + SLOT_TAG_LEN;
pub(super) const SLOT_LEN: usize = SLOT_SALT_LEN + SLOT_NONCE_LEN + SLOT_CIPHERTEXT_LEN;
const DATA_START: u64 = (HEADER_LEN + SLOT_COUNT * SLOT_LEN) as u64;
const FOOTER_LEN: u64 = 20;
const FOOTER_MAGIC: &[u8; 4] = b"1TLV";
const VERSION: u16 = 1;
const ROLE_NORMAL: u8 = 1;
const ROLE_BURN: u8 = 2;
const MODE_ERROR: u8 = 0;
const MODE_DECOY: u8 = 1;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("invalid password")]
    InvalidPassword,
    #[error("invalid vault format")]
    InvalidFormat,
    #[error("invalid entry name")]
    InvalidEntryName,
    #[error("burn password is too similar to the main password")]
    SimilarPasswords,
    #[error("this decoy vault is read-only")]
    DecoyReadOnly,
    #[error("vault entry not found")]
    EntryNotFound,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisguiseMode {
    Error,
    Decoy,
}

impl DisguiseMode {
    fn as_byte(self) -> u8 {
        match self {
            Self::Error => MODE_ERROR,
            Self::Decoy => MODE_DECOY,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultEntry {
    pub name: String,
    pub offset: u64,
    pub len: u64,
}

pub struct Vault {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    entries: Vec<VaultEntry>,
    decoy: bool,
}

impl Vault {
    pub fn create(
        path: impl AsRef<Path>,
        password: &str,
        burn_password: Option<&str>,
        disguise: DisguiseMode,
    ) -> Result<Self, VaultError> {
        if password.is_empty() {
            return Err(VaultError::InvalidPassword);
        }
        if burn_password.is_some_and(|burn| passwords_are_similar(password, burn)) {
            return Err(VaultError::SimilarPasswords);
        }

        let path = path.as_ref().to_path_buf();
        let key = Zeroizing::new(crypto::random_bytes::<32>());
        let mut file = OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(b"VLT1")?;
        file.write_all(&VERSION.to_le_bytes())?;
        file.write_all(&0u16.to_le_bytes())?;

        let normal_slot = crypto::make_slot(password, ROLE_NORMAL, MODE_ERROR, &key);
        let burn_slot =
            burn_password.map(|burn| crypto::make_slot(burn, ROLE_BURN, disguise.as_byte(), &key));
        file.write_all(&normal_slot)?;
        if let Some(slot) = burn_slot {
            file.write_all(&slot)?;
        } else {
            let mut slot = [0; SLOT_LEN];
            OsRng.fill_bytes(&mut slot);
            file.write_all(&slot)?;
        }
        for _ in 0..SLOT_COUNT - 2 {
            let mut slot = [0; SLOT_LEN];
            OsRng.fill_bytes(&mut slot);
            file.write_all(&slot)?;
        }
        let mut vault = Self {
            path,
            key,
            entries: Vec::new(),
            decoy: false,
        };
        vault.write_index(&mut file)?;
        Ok(vault)
    }

    pub fn open(path: impl AsRef<Path>, password: &str) -> Result<Self, VaultError> {
        let path = path.as_ref().to_path_buf();
        let mut file = File::open(&path)?;
        let file_len = file.metadata()?.len();
        if file_len < DATA_START + FOOTER_LEN {
            return Err(VaultError::InvalidFormat);
        }
        let mut header = [0; HEADER_LEN];
        file.read_exact(&mut header)?;
        if &header[..4] != b"VLT1" || u16::from_le_bytes([header[4], header[5]]) != VERSION {
            return Err(VaultError::InvalidFormat);
        }

        let mut unlocked = None;
        for index in 0..SLOT_COUNT {
            let mut slot = [0; SLOT_LEN];
            file.seek(SeekFrom::Start((HEADER_LEN + index * SLOT_LEN) as u64))?;
            file.read_exact(&mut slot)?;
            if let Some(payload) = crypto::open_slot(password, &slot) {
                if payload.len() == 34 && unlocked.is_none() {
                    unlocked = Some(payload);
                }
            }
        }

        let Some(payload) = unlocked else {
            thread::sleep(Duration::from_millis(500));
            return Err(VaultError::InvalidPassword);
        };
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(&payload[2..]);
        match payload[0] {
            ROLE_NORMAL => {
                let entries = Self::read_index(&mut file, file_len, &key)?;
                Ok(Self {
                    path,
                    key,
                    entries,
                    decoy: false,
                })
            }
            ROLE_BURN => {
                drop(file);
                shred::shred(&path)?;
                if payload[1] == MODE_DECOY {
                    Ok(Self {
                        path,
                        key: Zeroizing::new(crypto::random_bytes::<32>()),
                        entries: Vec::new(),
                        decoy: true,
                    })
                } else {
                    thread::sleep(Duration::from_millis(500));
                    Err(VaultError::InvalidPassword)
                }
            }
            _ => {
                thread::sleep(Duration::from_millis(500));
                Err(VaultError::InvalidPassword)
            }
        }
    }

    pub fn entries(&self) -> &[VaultEntry] {
        &self.entries
    }

    pub fn read_entry(&self, name: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.name == name)
            .ok_or(VaultError::EntryNotFound)?;
        let mut file = File::open(&self.path)?;
        file.seek(SeekFrom::Start(entry.offset))?;
        let length = usize::try_from(entry.len).map_err(|_| VaultError::InvalidFormat)?;
        let mut encrypted = vec![0; length];
        file.read_exact(&mut encrypted)?;
        crypto::decrypt(&self.key, &encrypted, b"VLT1 file").ok_or(VaultError::InvalidFormat)
    }

    pub fn add_entry(&mut self, name: &str, plaintext: &[u8]) -> Result<(), VaultError> {
        if self.decoy {
            return Err(VaultError::DecoyReadOnly);
        }
        let name = normalize_entry_name(name)?;
        let mut file = OpenOptions::new().read(true).write(true).open(&self.path)?;
        file.seek(SeekFrom::End(0))?;
        let offset = file.stream_position()?;
        let encrypted =
            crypto::encrypt(&self.key, plaintext, b"VLT1 file").ok_or(VaultError::InvalidFormat)?;
        file.write_all(&encrypted)?;
        self.entries.retain(|entry| entry.name != name);
        self.entries.push(VaultEntry {
            name,
            offset,
            len: encrypted.len() as u64,
        });
        self.write_index(&mut file)?;
        Ok(())
    }

    pub fn delete_entry(&mut self, name: &str) -> Result<(), VaultError> {
        if self.decoy {
            return Err(VaultError::DecoyReadOnly);
        }
        let original_len = self.entries.len();
        self.entries.retain(|entry| entry.name != name);
        if self.entries.len() == original_len {
            return Err(VaultError::EntryNotFound);
        }
        let mut file = OpenOptions::new().read(true).write(true).open(&self.path)?;
        file.seek(SeekFrom::End(0))?;
        self.write_index(&mut file)
    }

    pub fn compact(&mut self) -> Result<(), VaultError> {
        if self.decoy {
            return Err(VaultError::DecoyReadOnly);
        }
        let mut source = File::open(&self.path)?;
        let mut bytes = Vec::with_capacity(DATA_START as usize);
        bytes.extend_from_slice(b"VLT1");
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        for index in 0..SLOT_COUNT {
            let mut slot = [0; SLOT_LEN];
            source.seek(SeekFrom::Start((HEADER_LEN + index * SLOT_LEN) as u64))?;
            source.read_exact(&mut slot)?;
            bytes.extend_from_slice(&slot);
        }

        let mut compacted_entries = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let plaintext = self.read_entry(&entry.name)?;
            let encrypted = crypto::encrypt(&self.key, &plaintext, b"VLT1 file")
                .ok_or(VaultError::InvalidFormat)?;
            let offset = bytes.len() as u64;
            bytes.extend_from_slice(&encrypted);
            compacted_entries.push(VaultEntry {
                name: entry.name.clone(),
                offset,
                len: encrypted.len() as u64,
            });
        }
        let index_json = Zeroizing::new(serde_json::to_vec(&compacted_entries)?);
        let encrypted_index = crypto::encrypt(&self.key, &index_json, b"VLT1 index")
            .ok_or(VaultError::InvalidFormat)?;
        let index_offset = bytes.len() as u64;
        bytes.extend_from_slice(&encrypted_index);
        bytes.extend_from_slice(&index_offset.to_le_bytes());
        bytes.extend_from_slice(&(encrypted_index.len() as u64).to_le_bytes());
        bytes.extend_from_slice(FOOTER_MAGIC);

        let temp_path = temporary_path(&self.path);
        let mut temp = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        temp.write_all(&bytes)?;
        temp.sync_all()?;
        drop(temp);

        let backup_path = temporary_path(&self.path);
        if let Err(error) = fs::rename(&self.path, &backup_path) {
            let _ = fs::remove_file(&temp_path);
            return Err(error.into());
        }
        if let Err(error) = fs::rename(&temp_path, &self.path) {
            let _ = fs::rename(&backup_path, &self.path);
            let _ = fs::remove_file(&temp_path);
            return Err(error.into());
        }
        self.entries = compacted_entries;
        fs::remove_file(backup_path)?;
        Ok(())
    }

    fn write_index(&mut self, file: &mut File) -> Result<(), VaultError> {
        let index_json = Zeroizing::new(serde_json::to_vec(&self.entries)?);
        let encrypted = crypto::encrypt(&self.key, &index_json, b"VLT1 index")
            .ok_or(VaultError::InvalidFormat)?;
        let offset = file.seek(SeekFrom::End(0))?;
        file.write_all(&encrypted)?;
        file.write_all(&offset.to_le_bytes())?;
        file.write_all(&(encrypted.len() as u64).to_le_bytes())?;
        file.write_all(FOOTER_MAGIC)?;
        file.sync_all()?;
        Ok(())
    }

    fn read_index(
        file: &mut File,
        file_len: u64,
        key: &[u8; 32],
    ) -> Result<Vec<VaultEntry>, VaultError> {
        file.seek(SeekFrom::End(-(FOOTER_LEN as i64)))?;
        let mut footer = [0; FOOTER_LEN as usize];
        file.read_exact(&mut footer)?;
        if &footer[16..] != FOOTER_MAGIC {
            return Err(VaultError::InvalidFormat);
        }
        let offset = u64::from_le_bytes(footer[..8].try_into().unwrap());
        let length = u64::from_le_bytes(footer[8..16].try_into().unwrap());
        let end = offset
            .checked_add(length)
            .ok_or(VaultError::InvalidFormat)?;
        if offset < DATA_START || end != file_len - FOOTER_LEN || length < 28 {
            return Err(VaultError::InvalidFormat);
        }
        let length_usize = usize::try_from(length).map_err(|_| VaultError::InvalidFormat)?;
        let mut encrypted = vec![0; length_usize];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut encrypted)?;
        let plaintext =
            crypto::decrypt(key, &encrypted, b"VLT1 index").ok_or(VaultError::InvalidFormat)?;
        let entries: Vec<VaultEntry> = serde_json::from_slice(&plaintext)?;
        for entry in &entries {
            let entry_end = entry
                .offset
                .checked_add(entry.len)
                .ok_or(VaultError::InvalidFormat)?;
            if entry.offset < DATA_START || entry.len < 28 || entry_end > offset {
                return Err(VaultError::InvalidFormat);
            }
            normalize_entry_name(&entry.name)?;
        }
        Ok(entries)
    }
}

fn normalize_entry_name(name: &str) -> Result<String, VaultError> {
    let normalized = name.trim().replace('\\', "/");
    if normalized.is_empty()
        || normalized.starts_with('/')
        || normalized.contains(':')
        || normalized
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(VaultError::InvalidEntryName);
    }
    Ok(normalized)
}

fn normalized_password(password: &str) -> String {
    password.trim().to_lowercase()
}

fn passwords_are_similar(normal: &str, burn: &str) -> bool {
    let normal = normalized_password(normal);
    let burn = normalized_password(burn);
    let left: Vec<char> = normal.chars().collect();
    let right: Vec<char> = burn.chars().collect();
    if left.is_empty() || right.is_empty() {
        return true;
    }
    if left.len().abs_diff(right.len()) > 1 {
        return false;
    }
    let mut previous: Vec<usize> = (0..=right.len()).collect();
    for (i, left_char) in left.iter().enumerate() {
        let mut current = vec![i + 1; right.len() + 1];
        for (j, right_char) in right.iter().enumerate() {
            current[j + 1] = (previous[j + 1] + 1)
                .min(current[j] + 1)
                .min(previous[j] + usize::from(left_char != right_char));
        }
        previous = current;
    }
    previous[right.len()] <= 1
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut random = [0; 16];
    OsRng.fill_bytes(&mut random);
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    path.with_extension(format!("vlt-{suffix}.tmp"))
}

#[cfg(test)]
mod tests {
    use std::{fs, time::Instant};

    use super::*;

    fn new_vault() -> (tempfile::TempDir, PathBuf, Vault) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("test.vlt");
        let vault = Vault::create(
            &path,
            "correct horse",
            Some("burn-safe"),
            DisguiseMode::Error,
        )
        .unwrap();
        (directory, path, vault)
    }

    #[test]
    fn create_add_unlock_and_read_in_memory() {
        let (_directory, path, mut vault) = new_vault();
        vault
            .add_entry("notes/readme.md", b"# private note")
            .unwrap();
        drop(vault);

        let reopened = Vault::open(&path, "correct horse").unwrap();
        assert_eq!(reopened.entries()[0].name, "notes/readme.md");
        assert_eq!(
            &*reopened.read_entry("notes/readme.md").unwrap(),
            b"# private note"
        );
    }

    #[test]
    fn rejects_wrong_password_after_rate_limit() {
        let (_directory, path, _vault) = new_vault();
        let start = Instant::now();
        assert!(matches!(
            Vault::open(&path, "incorrect"),
            Err(VaultError::InvalidPassword)
        ));
        assert!(start.elapsed() >= Duration::from_millis(500));
    }

    #[test]
    fn burn_password_shreds_and_returns_generic_error() {
        let (_directory, path, _vault) = new_vault();
        assert!(matches!(
            Vault::open(&path, "burn-safe"),
            Err(VaultError::InvalidPassword)
        ));
        assert!(!path.exists());
    }

    #[test]
    fn decoy_burn_mode_returns_empty_read_only_vault() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("decoy.vlt");
        drop(Vault::create(&path, "normal-pass", Some("burn-pass"), DisguiseMode::Decoy).unwrap());
        let mut decoy = Vault::open(&path, "burn-pass").unwrap();
        assert!(decoy.entries().is_empty());
        assert!(matches!(
            decoy.add_entry("nope.txt", b"nope"),
            Err(VaultError::DecoyReadOnly)
        ));
        assert!(!path.exists());
    }

    #[test]
    fn rejects_similar_passwords_and_traversal_names() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("invalid.vlt");
        assert!(matches!(
            Vault::create(&path, "secret", Some("Secret "), DisguiseMode::Error),
            Err(VaultError::SimilarPasswords)
        ));
        let (_directory, _path, mut vault) = new_vault();
        assert!(matches!(
            vault.add_entry("../outside.txt", b"nope"),
            Err(VaultError::InvalidEntryName)
        ));
    }

    #[test]
    fn compact_reclaims_deleted_entry_space_and_preserves_data() {
        let (_directory, path, mut vault) = new_vault();
        vault.add_entry("keep.txt", &vec![b'a'; 2048]).unwrap();
        vault.add_entry("remove.txt", &vec![b'b'; 4096]).unwrap();
        vault.delete_entry("remove.txt").unwrap();
        let before = fs::metadata(&path).unwrap().len();
        vault.compact().unwrap();
        let after = fs::metadata(&path).unwrap().len();
        assert!(after < before);
        assert_eq!(vault.read_entry("keep.txt").unwrap().len(), 2048);
        drop(vault);
        assert_eq!(
            Vault::open(&path, "correct horse").unwrap().entries().len(),
            1
        );
    }
}
