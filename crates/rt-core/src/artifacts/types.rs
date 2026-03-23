use serde::{Deserialize, Serialize};

/// Forensic artifact types recognized by RapidTriage parsers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArtifactType {
    /// NTFS USN Change Journal ($UsnJrnl:$J)
    UsnJournal,
    /// NTFS Master File Table ($MFT)
    Mft,
    /// Windows Event Log (.evtx)
    EventLog,
    /// Windows Prefetch (.pf)
    Prefetch,
    /// Windows Registry hive
    Registry,
    /// Windows Shellbags
    Shellbags,
    /// Windows LNK shortcut files
    Lnk,
    /// Application Compatibility Cache (Amcache.hve)
    Amcache,
    /// Background Activity Moderator
    Bam,
    /// Browser history (Chrome, Firefox, Edge)
    BrowserHistory,
    /// Windows Jump Lists
    JumpLists,
    /// System Resource Usage Monitor (SRUM)
    Srum,
}

impl std::fmt::Display for ArtifactType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UsnJournal => write!(f, "USN Journal"),
            Self::Mft => write!(f, "MFT"),
            Self::EventLog => write!(f, "Event Log"),
            Self::Prefetch => write!(f, "Prefetch"),
            Self::Registry => write!(f, "Registry"),
            Self::Shellbags => write!(f, "Shellbags"),
            Self::Lnk => write!(f, "LNK"),
            Self::Amcache => write!(f, "Amcache"),
            Self::Bam => write!(f, "BAM"),
            Self::BrowserHistory => write!(f, "Browser History"),
            Self::JumpLists => write!(f, "Jump Lists"),
            Self::Srum => write!(f, "SRUM"),
        }
    }
}
