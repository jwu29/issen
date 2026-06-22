use std::fmt;
use std::path::PathBuf;

/// A file path that may exist simultaneously in Windows (NTFS) and WSL (ext4/DrvFs)
/// address spaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HybridPath {
    /// A Windows NTFS path with no standard drive letter (UNC, etc.).
    Windows(PathBuf),
    /// A native WSL Linux path — not under /mnt/<drive>/.
    Wsl(PathBuf),
    /// A DrvFs path: simultaneously accessible as a Windows drive path and /mnt/<drive>/... in WSL.
    DrvFs { windows: PathBuf, wsl: PathBuf },
}

impl HybridPath {
    /// Construct from a WSL absolute path string.
    ///
    /// `/mnt/<drive>/...` → `DrvFs`; everything else → `Wsl`.
    pub fn from_wsl_str(s: &str) -> Self {
        if let Some(rest) = s.strip_prefix("/mnt/") {
            // rest must have at least a single-char drive and a separator
            let mut chars = rest.chars();
            let drive = match chars.next() {
                Some(c) if c.is_ascii_alphabetic() => c,
                _ => return Self::Wsl(PathBuf::from(s)),
            };
            match chars.next() {
                // /mnt/<drive>/ or /mnt/<drive> followed by end
                Some('/') | None => {
                    let after_drive = &rest[drive.len_utf8()..]; // starts with '/' or empty
                    let after_slash = after_drive.trim_start_matches('/');
                    let win_rest = after_slash.replace('/', "\\");
                    let win_path = if win_rest.is_empty() {
                        PathBuf::from(format!("{}:\\", drive.to_ascii_uppercase()))
                    } else {
                        PathBuf::from(format!("{}:\\{}", drive.to_ascii_uppercase(), win_rest))
                    };
                    Self::DrvFs {
                        windows: win_path,
                        wsl: PathBuf::from(s),
                    }
                }
                _ => Self::Wsl(PathBuf::from(s)),
            }
        } else {
            Self::Wsl(PathBuf::from(s))
        }
    }

    /// Construct from a Windows absolute path string.
    ///
    /// `<Drive>:\...` → `DrvFs`; UNC/other → `Windows`.
    pub fn from_windows_str(s: &str) -> Self {
        let bytes = s.as_bytes();
        if bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && (bytes[2] == b'\\' || bytes[2] == b'/')
        {
            let drive = (bytes[0] as char).to_ascii_lowercase();
            let rest = &s[3..];
            let wsl_rest = rest.replace('\\', "/");
            let wsl_path = if wsl_rest.is_empty() {
                PathBuf::from(format!("/mnt/{drive}/"))
            } else {
                PathBuf::from(format!("/mnt/{drive}/{wsl_rest}"))
            };
            Self::DrvFs {
                windows: PathBuf::from(s),
                wsl: wsl_path,
            }
        } else {
            Self::Windows(PathBuf::from(s))
        }
    }

    /// Returns `true` if this is a DrvFs path.
    pub fn is_drvfs(&self) -> bool {
        matches!(self, Self::DrvFs { .. })
    }

    /// Returns the Windows path form if available.
    pub fn windows_path(&self) -> Option<&PathBuf> {
        match self {
            Self::Windows(p) | Self::DrvFs { windows: p, .. } => Some(p),
            Self::Wsl(_) => None,
        }
    }

    /// Returns the WSL path form if available.
    pub fn wsl_path(&self) -> Option<&PathBuf> {
        match self {
            Self::Wsl(p) | Self::DrvFs { wsl: p, .. } => Some(p),
            Self::Windows(_) => None,
        }
    }

    /// Canonical key for equality comparison (case-folded Windows path string).
    fn canonical_key(&self) -> String {
        match self {
            Self::DrvFs { windows, .. } => windows.to_string_lossy().to_ascii_uppercase(),
            Self::Windows(p) => p.to_string_lossy().to_ascii_uppercase(),
            Self::Wsl(p) => p.to_string_lossy().into_owned(),
        }
    }

    /// Returns `true` if `other` refers to the same file.
    pub fn same_file(&self, other: &HybridPath) -> bool {
        self.canonical_key() == other.canonical_key()
    }
}

impl fmt::Display for HybridPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Windows(p) | Self::Wsl(p) => write!(f, "{}", p.display()),
            Self::DrvFs { windows, wsl } => {
                write!(f, "{} (WSL: {})", windows.display(), wsl.display())
            }
        }
    }
}
