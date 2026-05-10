use std::fmt;
use std::path::PathBuf;

/// A file path that may exist simultaneously in Windows (NTFS) and WSL (ext4/DrvFs)
/// address spaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HybridPath {
    /// A Windows NTFS path (no WSL equivalent because it is not a standard drive letter).
    Windows(PathBuf),
    /// A native WSL Linux path (no Windows equivalent — not under /mnt/<drive>/).
    Wsl(PathBuf),
    /// A DrvFs path: accessible as both a Windows drive path and /mnt/<drive>/... in WSL.
    DrvFs { windows: PathBuf, wsl: PathBuf },
}

impl HybridPath {
    /// Construct from a WSL absolute path string.
    pub fn from_wsl_str(_s: &str) -> Self {
        todo!("implement from_wsl_str")
    }

    /// Construct from a Windows absolute path string.
    pub fn from_windows_str(_s: &str) -> Self {
        todo!("implement from_windows_str")
    }

    /// Returns `true` if this is a DrvFs path (accessible from both Windows and WSL).
    pub fn is_drvfs(&self) -> bool {
        todo!("implement is_drvfs")
    }

    /// Returns the Windows path form if available.
    pub fn windows_path(&self) -> Option<&PathBuf> {
        todo!("implement windows_path")
    }

    /// Returns the WSL path form if available.
    pub fn wsl_path(&self) -> Option<&PathBuf> {
        todo!("implement wsl_path")
    }

    /// Returns `true` if `other` refers to the same file as `self`.
    /// Two DrvFs paths are the same file if their canonical forms match.
    pub fn same_file(&self, other: &HybridPath) -> bool {
        todo!("implement same_file")
    }
}

impl fmt::Display for HybridPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!("implement Display")
    }
}
