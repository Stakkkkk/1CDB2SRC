//! Helpers shared by the external-object (.epf/.erf) tests.
#![allow(dead_code)]

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

pub fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/external")
        .join(name)
}

/// Every file under `root` by its `/`-separated relative path.
pub fn files(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    if !root.exists() {
        return out;
    }
    for entry in walkdir::WalkDir::new(root) {
        let entry = entry.expect("walk");
        if entry.file_type().is_file() {
            let rel = entry
                .path()
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            out.insert(rel, fs::read(entry.path()).unwrap());
        }
    }
    out
}

pub fn assert_tree_eq(expected: &Path, actual: &Path) {
    let (e, a) = (files(expected), files(actual));
    let missing: Vec<_> = e.keys().filter(|k| !a.contains_key(*k)).collect();
    let extra: Vec<_> = a.keys().filter(|k| !e.contains_key(*k)).collect();
    let differ: Vec<_> = e
        .keys()
        .filter(|k| a.get(*k).is_some_and(|v| v != &e[*k]))
        .collect();
    assert!(
        missing.is_empty() && extra.is_empty() && differ.is_empty(),
        "tree mismatch\n missing: {missing:?}\n extra: {extra:?}\n differ: {differ:?}"
    );
}

pub fn export(input: &Path, out: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ibcmd-rs"))
        .args(["cf", "export"])
        .arg(input)
        .arg(out)
        .args(["--source-version", "2.20", "--overwrite"])
        .output()
        .expect("run ibcmd-rs")
}

/// A scratch directory per test tag, cleared here and reused by the next run
/// (a per-process name left a new one behind on every run).
pub fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ibcmd-external-{tag}"));
    let _ = fs::remove_dir_all(&dir);
    dir
}
