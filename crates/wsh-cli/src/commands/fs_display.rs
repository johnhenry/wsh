//! Shared rendering for `wsh ls` and `wsh sftp` (wsh #58).
//!
//! Both commands print the same `FileEntry` list (wsh #59), so the
//! formatting logic lives in one place rather than being copied between
//! them and drifting -- the same "one parser, not two" reasoning wsh #58
//! applies to `[user@]host:path` parsing (see `common::parse_endpoint`)
//! applies here to rendering.

use wsh_core::messages::{FileEntry, FileEntryType};

/// Render one entry the way `ls -l`/`sftp`'s `ls` would, but honestly: a
/// symlink is shown as `name@ -> target`, never silently followed or
/// flattened into "file" -- wsh #58's "a browse surface that flattens that
/// is lying about the remote filesystem".
pub fn format_entry_line(entry: &FileEntry) -> String {
    let type_label = type_label(&entry.r#type);
    let marker = type_marker(&entry.r#type);
    let date = format_epoch_secs(entry.modified);

    let name_field = match (&entry.r#type, &entry.symlink_target) {
        (FileEntryType::Symlink, Some(target)) => format!("{}{marker} -> {target}", entry.name),
        _ => format!("{}{marker}", entry.name),
    };

    format!("{type_label:<8} {:>12} {date}  {name_field}", entry.size)
}

/// Short label for a `FileEntryType`, used both in `ls`/`sftp` listings
/// and anywhere else a human-readable type name is wanted.
pub fn type_label(t: &FileEntryType) -> &'static str {
    match t {
        FileEntryType::File => "file",
        FileEntryType::Directory => "dir",
        FileEntryType::Symlink => "symlink",
        FileEntryType::Device => "device",
        FileEntryType::Pipe => "pipe",
        FileEntryType::Socket => "socket",
    }
}

fn type_marker(t: &FileEntryType) -> &'static str {
    match t {
        FileEntryType::Directory => "/",
        FileEntryType::Symlink => "@",
        _ => "",
    }
}

/// Format a Unix epoch-seconds timestamp as `YYYY-MM-DD HH:MM` UTC.
///
/// `FileEntry.modified` (wsh #59) is a plain epoch-seconds u64 rather than
/// a locale-formatted string (the old `ls -la`-over-exec parsing in
/// `src/file-transfer.mjs` produced e.g. `"Jan 15 12:00"`, ambiguous
/// without a year and not sortable) -- this is the CLI-side presentation
/// of that typed value. No `time`/`chrono` dependency: a Gregorian
/// civil-date conversion is < 20 lines (Howard Hinnant's `civil_from_days`
/// algorithm, public domain).
pub fn format_epoch_secs(epoch: u64) -> String {
    let days = (epoch / 86_400) as i64;
    let secs_of_day = epoch % 86_400;
    let (y, m, d) = civil_from_days(days);
    let h = secs_of_day / 3600;
    let mi = (secs_of_day % 3600) / 60;
    format!("{y:04}-{m:02}-{d:02} {h:02}:{mi:02}")
}

/// Days-since-epoch (1970-01-01) to (year, month, day). Howard Hinnant's
/// `civil_from_days`, http://howardhinnant.github.io/date_algorithms.html
/// (public domain).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, size: u64, t: FileEntryType) -> FileEntry {
        FileEntry {
            name: name.to_string(),
            size,
            modified: 1_700_000_000, // 2023-11-14 22:13 UTC
            r#type: t,
            symlink_target: None,
        }
    }

    #[test]
    fn epoch_zero_is_unix_epoch() {
        assert_eq!(format_epoch_secs(0), "1970-01-01 00:00");
    }

    #[test]
    fn known_epoch_value() {
        // 1700000000 -> 2023-11-14 22:13:20 UTC (independently verified).
        assert_eq!(format_epoch_secs(1_700_000_000), "2023-11-14 22:13");
    }

    #[test]
    fn directory_gets_trailing_slash() {
        let e = entry("subdir", 0, FileEntryType::Directory);
        let line = format_entry_line(&e);
        assert!(line.contains("subdir/"));
        assert!(line.contains("dir"));
    }

    #[test]
    fn symlink_shows_arrow_to_target() {
        let mut e = entry("link", 0, FileEntryType::Symlink);
        e.symlink_target = Some("/real/path".to_string());
        let line = format_entry_line(&e);
        assert!(line.contains("link@ -> /real/path"));
    }

    #[test]
    fn symlink_without_target_still_marked_as_symlink_not_file() {
        let e = entry("dangling", 0, FileEntryType::Symlink);
        let line = format_entry_line(&e);
        assert!(line.contains("symlink"));
        assert!(!line.contains("dangling -> "));
    }

    #[test]
    fn plain_file_has_no_marker() {
        let e = entry("readme.txt", 42, FileEntryType::File);
        let line = format_entry_line(&e);
        assert!(line.contains("readme.txt"));
        assert!(!line.contains("readme.txt/"));
        assert!(!line.contains("readme.txt@"));
    }
}
