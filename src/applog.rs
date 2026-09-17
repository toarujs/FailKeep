//! Simple size-based rotating file logger (stdout + optional file).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

struct RotatingFile {
    path: PathBuf,
    max_bytes: u64,
    file: File,
}

impl RotatingFile {
    fn open(path: &Path, max_bytes: u64) -> std::io::Result<Self> {
        if let Some(p) = path.parent() {
            let _ = std::fs::create_dir_all(p);
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            max_bytes,
            file,
        })
    }

    fn write_line(&mut self, line: &str) {
        let _ = writeln!(self.file, "{line}");
        let _ = self.file.flush();
        if let Ok(meta) = self.file.metadata() {
            if meta.len() > self.max_bytes {
                let _ = self.file.flush();
                let bak = self.path.with_extension("log.1");
                let _ = std::fs::remove_file(&bak);
                let _ = std::fs::rename(&self.path, &bak);
                if let Ok(f) = OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&self.path)
                {
                    self.file = f;
                }
            }
        }
    }
}

static FILE_LOG: Mutex<Option<RotatingFile>> = Mutex::new(None);

pub fn init_file(path: &str, max_bytes: u64) {
    if path.is_empty() {
        return;
    }
    match RotatingFile::open(Path::new(path), max_bytes) {
        Ok(f) => {
            *FILE_LOG.lock().unwrap() = Some(f);
        }
        Err(e) => eprintln!("FailKeep: cannot open log file {path}: {e}"),
    }
}

pub fn log_line(line: &str) {
    if let Ok(mut g) = FILE_LOG.lock() {
        if let Some(f) = g.as_mut() {
            f.write_line(line);
        }
    }
}
