//! Forensic narrative patterns spanning Windows and WSL address spaces.

/// A detected cross-domain forensic pattern.
#[derive(Debug, Clone)]
pub enum HybridPattern {
    /// A file was downloaded via Windows browser then executed in WSL.
    BrowserToWslExecution {
        download_path: String,
        wsl_command: String,
    },
    /// A file in the DrvFs mount was exfiltrated via network from WSL.
    DrvFsExfiltration {
        file_path: String,
        destination: String,
    },
    /// A WSL tool was installed then used (e.g. apt install nmap; nmap ...).
    WslToolInstallAndUse {
        install_command: String,
        use_commands: Vec<String>,
    },
}
