use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    Ls { path: String },
    Cd { path: String },
    Pwd,
    Get { path: String },
    Put { path: String, size: u64, mode: u32 },
    Mkdir { path: String },
    Rmdir { path: String },
    Rm { path: String },
    Rename { from: String, to: String },
    Chmod { path: String, mode: u32 },
    Stat { path: String },
    Quit,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Ok,
    Err(String),
    DirListing(Vec<DirEntry>),
    Path(String),
    FileStat(FileStat),
    FileReady { size: u64 },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: u64,
    pub mode: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileStat {
    pub size: u64,
    pub is_dir: bool,
    pub modified: u64,
    pub mode: u32,
}
