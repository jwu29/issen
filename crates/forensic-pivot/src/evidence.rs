// RED: stub — types declared but no real logic
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EvidenceSource {
    Sigma,
    Yara,
    Suricata,
    Zeek,
    Memory,
    Artifact,
    Manual,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EvidenceKind {
    ProcessName,
    Port,
    IpAddress,
    FilePath,
    Hash,
    Command,
    Tag,
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SubjectRef {
    Process {
        pid: Option<u32>,
        name: String,
    },
    File {
        path: String,
    },
    Network {
        src_ip: Option<String>,
        dst_ip: Option<String>,
        dst_port: Option<u16>,
    },
    User {
        name: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: String,
    pub source: EvidenceSource,
    pub kind: EvidenceKind,
    pub value: String,
    pub subject: Option<SubjectRef>,
    pub timestamp_ns: Option<i64>,
    pub confidence: u8,
    pub attrs: HashMap<String, String>,
}
