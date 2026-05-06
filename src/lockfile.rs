use crate::error::Error;
use std::path::Path;

#[derive(Clone)]
pub struct Package {
    pub name: String,
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub hash: Vec<u8>,
    pub dependencies: Vec<String>,
}

pub fn serialize(_packages: &mut Vec<Package>) -> Result<String, Error> {
    todo!()
}

pub fn deserialize(_content: &str) -> Result<Vec<Package>, Error> {
    todo!()
}

pub fn write_lockfile(_path: &Path, _packages: &mut Vec<Package>) -> Result<(), Error> {
    todo!()
}

pub fn read_lockfile(_path: &Path) -> Result<Vec<Package>, Error> {
    todo!()
}
