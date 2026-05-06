use crate::error::Error;
use std::path::Path;
use std::fs;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Registry(String),
    Local(String),
    Git(String),
    Workspace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha512,
    Blake3,
}

#[derive(Debug, Clone)]
pub struct IntegrityHash {
    pub algo: HashAlgorithm,
    pub digest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepType {
    Runtime,
    Dev,
    Peer,
    Optional,
}

#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    pub dep_type: DepType,
}

#[derive(Debug, Clone)]
pub struct Override {
    pub name: String,
    pub from_version: String,
    pub to_version: String,
}

#[derive(Debug, Clone)]
pub struct Package {
    pub name: String,
    pub source_idx: usize,
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub hashes: Vec<IntegrityHash>,
    pub dependencies: Vec<Dependency>,
}

#[derive(Debug, Clone)]
pub struct Lockfile {
    pub sources: Vec<Source>,
    pub overrides: Vec<Override>,
    pub packages: Vec<Package>,
}

pub fn serialize(_lockfile: &mut Lockfile) -> Result<String, Error> {
    todo!()
}

pub fn deserialize(_content: &str) -> Result<Lockfile, Error> {
    todo!()
}

pub fn write_lockfile(path: &Path, lockfile: &mut Lockfile) -> Result<(), Error> {
    let content = serialize(lockfile)?;
    fs::write(path, content)?;
    Ok(())
}

pub fn read_lockfile(path: &Path) -> Result<Lockfile, Error> {
    let content = fs::read_to_string(path)?;
    deserialize(&content)
}
