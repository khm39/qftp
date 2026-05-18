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

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip_request(req: &Request) -> Request {
        let bytes = bincode::serialize(req).unwrap();
        bincode::deserialize(&bytes).unwrap()
    }

    fn round_trip_response(resp: &Response) -> Response {
        let bytes = bincode::serialize(resp).unwrap();
        bincode::deserialize(&bytes).unwrap()
    }

    #[test]
    fn put_request_round_trip() {
        let req = Request::Put {
            path: "dir/file.bin".into(),
            size: 12345,
            mode: 0o644,
        };
        match round_trip_request(&req) {
            Request::Put { path, size, mode } => {
                assert_eq!(path, "dir/file.bin");
                assert_eq!(size, 12345);
                assert_eq!(mode, 0o644);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn dir_listing_round_trip() {
        let resp = Response::DirListing(vec![DirEntry {
            name: "a".into(),
            is_dir: false,
            size: 1,
            modified: 2,
            mode: 0o600,
        }]);
        match round_trip_response(&resp) {
            Response::DirListing(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].name, "a");
                assert_eq!(entries[0].mode, 0o600);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn file_ready_response_round_trip() {
        let resp = Response::FileReady { size: 99 };
        match round_trip_response(&resp) {
            Response::FileReady { size } => assert_eq!(size, 99),
            other => panic!("unexpected variant: {other:?}"),
        }
    }
}
