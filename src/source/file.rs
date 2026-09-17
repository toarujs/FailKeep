use crate::config::SourceConfig;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use time::format_description::well_known::Rfc3339;
use time::{format_description, OffsetDateTime, PrimitiveDateTime, UtcOffset};

/// Incremental file tailer with rotation detection.
pub struct FileTailer {
    path_glob: String,
    /// path -> byte offset already consumed
    offsets: HashMap<PathBuf, u64>,
}

impl FileTailer {
    pub fn new(path_glob: impl Into<String>) -> Self {
        Self {
            path_glob: path_glob.into(),
            offsets: HashMap::new(),
        }
    }

    pub fn from_source(src: &SourceConfig) -> Option<Self> {
        match src {
            SourceConfig::File { path, .. }
            | SourceConfig::Iis { path, .. }
            | SourceConfig::Fwlog { path } => Some(Self::new(path.clone())),
            SourceConfig::Eventlog { .. } => None,
        }
    }

    /// Read newly appended complete lines from all matching files.
    pub fn read_new_lines(&mut self) -> Result<Vec<(PathBuf, String)>> {
        let mut out = Vec::new();
        for path in expand_paths(&self.path_glob)? {
            self.read_file_lines(&path, &mut out)?;
        }
        Ok(out)
    }

    fn read_file_lines(&mut self, path: &Path, out: &mut Vec<(PathBuf, String)>) -> Result<()> {
        let meta_len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        let mut offset = *self.offsets.get(path).unwrap_or(&0);
        // Rotation: file shrank → restart from 0
        if meta_len < offset {
            offset = 0;
        }
        if meta_len <= offset {
            return Ok(());
        }
        let mut f = OpenOptions::new()
            .read(true)
            .open(path)
            .with_context(|| format!("open {}", path.display()))?;
        f.seek(SeekFrom::Start(offset))?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        // Only consume up to last newline to avoid partial lines
        let consumed_end = match buf.iter().rposition(|&b| b == b'\n') {
            Some(i) => i + 1,
            None => return Ok(()),
        };
        let chunk = &buf[..consumed_end];
        let text = String::from_utf8_lossy(chunk);
        for line in text.lines() {
            let line = line.trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }
            out.push((path.to_path_buf(), line.to_string()));
        }
        self.offsets.insert(path.to_path_buf(), offset + consumed_end as u64);
        Ok(())
    }

    pub fn offsets_snapshot(&self) -> Vec<(PathBuf, u64)> {
        self.offsets
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect()
    }

    pub fn restore_offsets(&mut self, offsets: impl IntoIterator<Item = (PathBuf, u64)>) {
        for (p, o) in offsets {
            self.offsets.insert(p, o);
        }
    }

    pub fn restore_offset(&mut self, path: PathBuf, offset: u64) {
        self.offsets.insert(path, offset);
    }
}

/// Expand a path that may contain `*` in file name or one directory level.
/// Supports patterns like `C:\dir\u_ex*.log` and `C:\dir\*\u_ex*.log`.
pub fn expand_paths(pattern: &str) -> Result<Vec<PathBuf>> {
    if !pattern.contains('*') && !pattern.contains('?') {
        let p = PathBuf::from(pattern);
        return if p.exists() {
            Ok(vec![p])
        } else {
            Ok(vec![])
        };
    }
    let path = Path::new(pattern);
    let file_pat = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let parent = path.parent().map(|p| p.to_path_buf());
    let mut dirs = Vec::new();
    match parent {
        Some(par) => {
            let par_str = par.to_string_lossy();
            if par_str.contains('*') {
                // one-level wildcard in directory
                let grand = par.parent().map(|p| p.to_path_buf());
                let dir_pat = par
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();
                let grand = grand.unwrap_or_else(|| PathBuf::from("."));
                if let Ok(rd) = std::fs::read_dir(&grand) {
                    for e in rd.flatten() {
                        let name = e.file_name().to_string_lossy().to_string();
                        if wildcard_match(&dir_pat, &name) && e.path().is_dir() {
                            dirs.push(e.path());
                        }
                    }
                }
            } else {
                dirs.push(par);
            }
        }
        None => dirs.push(PathBuf::from(".")),
    }
    let mut files = Vec::new();
    for d in dirs {
        if let Ok(rd) = std::fs::read_dir(&d) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if wildcard_match(&file_pat, &name) && e.path().is_file() {
                    files.push(e.path());
                }
            }
        }
    }
    files.sort();
    Ok(files)
}

fn wildcard_match(pattern: &str, name: &str) -> bool {
    // simple * and ? matcher
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    fn rec(p: &[char], n: &[char]) -> bool {
        if p.is_empty() {
            return n.is_empty();
        }
        if p[0] == '*' {
            for i in 0..=n.len() {
                if rec(&p[1..], &n[i..]) {
                    return true;
                }
            }
            false
        } else if n.is_empty() {
            false
        } else if p[0] == '?' || p[0] == n[0] {
            rec(&p[1..], &n[1..])
        } else {
            false
        }
    }
    rec(&p, &n)
}

/// Parse a timestamp from a log line using optional regex + format.
pub fn parse_line_time(
    line: &str,
    re: Option<&regex::Regex>,
    fmt: Option<&str>,
) -> Option<OffsetDateTime> {
    let (cap, fmt) = match (re, fmt) {
        (Some(re), Some(fmt)) => (re.captures(line)?.name("ts")?.as_str().to_string(), fmt),
        _ => return None,
    };
    parse_datetime_str(&cap, fmt)
}

pub fn parse_datetime_str(s: &str, fmt: &str) -> Option<OffsetDateTime> {
    // Try with format description
    let desc = format_description::parse_borrowed::<2>(fmt).ok()?;
    if let Ok(pd) = PrimitiveDateTime::parse(s, &desc) {
        // assume UTC if naive — callers can refine later
        return Some(pd.assume_utc());
    }
    if let Ok(odt) = OffsetDateTime::parse(s, &desc) {
        return Some(odt);
    }
    // IIS often uses space-separated; also try common fallbacks
    None
}

/// Convert OffsetDateTime to unix seconds (i64).
pub fn to_unix(t: OffsetDateTime) -> i64 {
    t.unix_timestamp()
}

pub fn now_utc() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

/// IIS W3C helper: extract c-ip and sc-status from a data line given header field list.
pub fn parse_iis_fields(fields: &[&str], line: &str) -> Option<(String, u16)> {
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.len() < fields.len() {
        return None;
    }
    let mut ip = None;
    let mut status = None;
    for (i, f) in fields.iter().enumerate() {
        match *f {
            "c-ip" => ip = cols.get(i).map(|s| s.to_string()),
            "sc-status" => status = cols.get(i).and_then(|s| s.parse::<u16>().ok()),
            _ => {}
        }
    }
    Some((ip?, status?))
}

/// Build IIS field index from a `#Fields:` header line.
pub fn parse_iis_fields_header(line: &str) -> Option<Vec<String>> {
    let rest = line.trim().strip_prefix("#Fields:")?;
    Some(rest.split_whitespace().map(|s| s.to_string()).collect())
}

pub fn format_rfc3339(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_else(|_| t.to_string())
}

pub fn local_offset() -> UtcOffset {
    UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC)
}

#[allow(dead_code)]
fn _unused_open(_: &Path) -> Option<File> {
    None
}
