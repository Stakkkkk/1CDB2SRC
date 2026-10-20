//! Portable production-parser/renderer checks, independent of legacy corpora.
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use flate2::{Compression, write::DeflateEncoder};
use ibcmd_rs::cli::InfobaseConfigSourceVersion;
use ibcmd_rs::mssql_dump::{ForeignReferences, export_packed_entries_to_source};

const ROLE: &str = "aaaaaaaa-1234-4567-8901-000000000001";
const OWNER: &str = "bbbbbbbb-1234-4567-8901-000000000002";

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("ibcmd-rights-{}", uuid::Uuid::new_v4())))
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        if self.0.exists() {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
}

fn deflate(text: &str) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(text.as_bytes()).unwrap();
    encoder.finish().unwrap()
}

fn export(entries: Vec<(String, Vec<u8>)>, foreign: BTreeMap<String, String>, output: &Path) -> String {
    let report = export_packed_entries_to_source(
        "test:synthetic-rights", entries, output, false,
        InfobaseConfigSourceVersion::V2_20,
        Some(&ForeignReferences { objects: foreign, types: vec![] }),
    ).unwrap();
    assert_eq!(report.storage.failed, 0, "{report:?}");
    let files = walkdir::WalkDir::new(output).into_iter().map(Result::unwrap)
        .filter(|e| e.file_type().is_file() && e.file_name() == "Rights.xml")
        .map(|e| e.into_path()).collect::<Vec<_>>();
    assert_eq!(files.len(), 1, "{report:?}");
    fs::read_to_string(&files[0]).unwrap()
}

fn synthetic(kind: &str, pairs: &str) -> String {
    synthetic_body(kind, &format!("{{0,{pairs}}}"), false)
}

fn synthetic_body(kind: &str, rights: &str, set_for_new_objects: bool) -> String {
    let temp = Temp::new();
    let metadata = format!(
        "{{1,{{6,{{3,{{1,0,{ROLE}}},\"PortableRole\",{{0}},\"\",0,0,00000000-0000-0000-0000-000000000000,0}},1,0,0}},0}}"
    );
    let flag = usize::from(set_for_new_objects);
    let body = format!("{{10,{{1,{{{{1,{OWNER},0,0}},{rights}}}}},{{0}},{flag},1,0,4294967295}}");
    export(vec![(ROLE.into(), deflate(&metadata)), (format!("{ROLE}.0"), deflate(&body))],
        BTreeMap::from([(ROLE.into(), "Role.PortableRole".into()), (OWNER.into(), format!("{kind}.UnrelatedObject"))]), &temp.0)
}

fn names(xml: &str) -> Vec<String> {
    xml.split("<right>").skip(1).map(|part| {
        part.split("<name>").nth(1).unwrap().split("</name>").next().unwrap().to_string()
    }).collect()
}

#[test]
fn catalog_parser_renderer_orders_history_after_update_settings() {
    let xml = synthetic("Catalog", "9342b152-a7ae-4c79-9b7b-f4f028a36479,1,1c87578f-9e09-4ec0-a991-5629c87b1588,1,5b3ea0e2-fdb9-41f6-bf6c-25747906b4cb,1");
    assert_eq!(names(&xml), ["Read", "UpdateDataHistoryVersionComment", "ViewDataHistory"]);
}

#[test]
fn register_parser_renderer_orders_totals_before_history() {
    let xml = synthetic("InformationRegister", "9342b152-a7ae-4c79-9b7b-f4f028a36479,1,24abfe06-289a-48c5-8bb4-032c733e45c5,1,1c87578f-9e09-4ec0-a991-5629c87b1588,1");
    assert_eq!(names(&xml), ["Read", "TotalsControl", "ViewDataHistory"]);
}

#[test]
fn filtering_false_values_is_unchanged_by_ordering() {
    let xml = synthetic("Catalog", "9342b152-a7ae-4c79-9b7b-f4f028a36479,1,1c87578f-9e09-4ec0-a991-5629c87b1588,-1");
    assert_eq!(names(&xml), ["ViewDataHistory"]);
}

#[test]
fn false_exceptions_in_full_access_role_keep_their_values() {
    let xml = synthetic_body("InformationRegister", "{0,9342b152-a7ae-4c79-9b7b-f4f028a36479,-1,24abfe06-289a-48c5-8bb4-032c733e45c5,-1,1c87578f-9e09-4ec0-a991-5629c87b1588,1}", true);
    assert_eq!(names(&xml), ["TotalsControl", "ViewDataHistory"]);
    assert_eq!(xml.matches("<value>false</value>").count(), 2);
}

#[test]
fn restricted_false_right_is_retained_with_its_condition() {
    let xml = synthetic_body("Catalog", "{1,2,9342b152-a7ae-4c79-9b7b-f4f028a36479,1,1c87578f-9e09-4ec0-a991-5629c87b1588,-1,1,{1c87578f-9e09-4ec0-a991-5629c87b1588,{1,{1,\"WHERE Flag = TRUE\",0}}}}", false);
    assert_eq!(names(&xml), ["Read", "ViewDataHistory"]);
    assert!(xml.contains("<value>false</value>"));
    assert!(xml.contains("<condition>WHERE Flag = TRUE</condition>"));
    assert_eq!(xml.matches("<restrictionByCondition>").count(), 1);
}

#[test]
fn other_metadata_kinds_preserve_serialized_sequence() {
    let xml = synthetic("Document", "9342b152-a7ae-4c79-9b7b-f4f028a36479,1,1c87578f-9e09-4ec0-a991-5629c87b1588,1");
    assert_eq!(names(&xml), ["ViewDataHistory", "Read"]);
}

/// Optional private CF-derived samples; expected XML is never an exporter input.
#[test]
#[ignore = "requires BD017_RIGHTS_CASES, an external CF-derived input manifest"]
fn saved_cf_roles_export_without_control_inputs() {
    let manifest = std::env::var("BD017_RIGHTS_CASES").expect("BD017_RIGHTS_CASES is required");
    let manifest: serde_json::Value = serde_json::from_slice(&fs::read(manifest).unwrap()).unwrap();
    for case in manifest.as_array().unwrap() {
        let entries = case["entries"].as_array().unwrap().iter().map(|e| {
            (e["name"].as_str().unwrap().to_string(), fs::read(e["path"].as_str().unwrap()).unwrap())
        }).collect();
        let foreign = serde_json::from_value(case["foreign"].clone()).unwrap();
        let output = Path::new(case["output"].as_str().unwrap());
        export(entries, foreign, output);
    }
}
