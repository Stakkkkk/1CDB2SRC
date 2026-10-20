//! `cf export` of a configuration extension (.cfe): the extension's own
//! properties, controlled properties and extended root modules in
//! `Configuration.xml`, as 8.3.27.2214 dumps them. Each fixture is a file the
//! platform built beside its own dump (`_onecdec/make_extension_root_fixtures.py`,
//! `make_cfe_fixture.py`).

mod common;

use std::{fs, path::Path};

fn exported_configuration(input: &Path, tag: &str) -> Vec<u8> {
    let out = common::temp_dir(&format!("extension-{tag}"));
    let run = common::export(input, &out);
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    fs::read(out.join("Configuration.xml")).unwrap()
}

fn assert_same(expected: &Path, actual: &[u8], case: &str) {
    let expected = fs::read(expected).unwrap();
    assert!(
        expected == actual,
        "{case}: Configuration.xml differs\n--- native\n{}\n--- ours\n{}",
        String::from_utf8_lossy(&expected),
        String::from_utf8_lossy(actual)
    );
}

fn root_case(case: &str) {
    let dir = common::fixture("extension_roots").join(case);
    let out = common::temp_dir(&format!("extension-roots-case-{case}"));
    let run = common::export(&dir.join("input.cfe"), &out);
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    for file in ["Configuration.xml", "ConfigDumpInfo.xml"] {
        let actual = fs::read(out.join(file)).unwrap_or_default();
        assert_same(&dir.join(file), &actual, &format!("{case} {file}"));
    }
}

#[test]
fn clean_room_extension_root_matches_the_platform() {
    let dir = common::fixture("test_extension");
    let actual = exported_configuration(&dir.join("input.cfe"), "test_extension");
    assert_same(
        &dir.join("expected/Configuration.xml"),
        &actual,
        "test_extension",
    );
}

#[test]
fn root_values_away_from_their_defaults() {
    root_case("values");
}

#[test]
fn root_spellings_of_a_patch_without_mapping_by_ids() {
    root_case("spellings");
}

#[test]
fn extended_root_modules_and_command_interfaces() {
    root_case("modules");
}

#[test]
fn own_role_among_the_default_roles() {
    root_case("roles");
}

#[test]
fn root_saved_by_8_5_reads_as_8_3_27_dumps_it() {
    root_case("values_v85");
}

#[test]
fn unknown_root_property_degrades_only_the_root() {
    // A controlled property no probe has named: the root keeps the
    // pipeline's rendering and is reported failed; the rest still exports.
    let input = common::fixture("extension_roots/unknown_property/input.cfe");
    let out = common::temp_dir("extension-unknown");
    let run = common::export(&input, &out);
    let report = format!(
        "{}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(run.status.code(), Some(2), "{report}");
    assert!(!report.contains("\"export_failed\""), "{report}");
    assert!(
        report.contains("ffffffff-0000-4000-8000-000000000001"),
        "{report}"
    );
    assert!(out.join("Configuration.xml").exists());
    assert!(
        out.join("CommonModules/ТестРасширение_Модуль/Ext/Module.bsl")
            .exists()
    );
}

#[test]
fn a_configinfo_that_does_not_match_the_entries_degrades_only_config_dump_info() {
    // `test_extension` plus one entry its configinfo does not list
    // (`_onecdec/make_configinfo_mismatch_fixture.py`): ConfigDumpInfo.xml is
    // not written and `configinfo` is reported failed; the rest still exports.
    let input = common::fixture("configinfo_mismatch/input.cfe");
    let out = common::temp_dir("extension-configinfo-mismatch");
    let run = common::export(&input, &out);
    let report = format!(
        "{}{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(run.status.code(), Some(2), "{report}");
    assert!(!report.contains("\"export_failed\""), "{report}");
    assert!(report.contains("ConfigDumpInfo.xml"), "{report}");
    assert!(!out.join("ConfigDumpInfo.xml").exists());
    let expected = common::fixture("test_extension/expected");
    assert_same(
        &expected.join("Configuration.xml"),
        &fs::read(out.join("Configuration.xml")).unwrap_or_default(),
        "configinfo_mismatch",
    );
    assert!(out.join("CommonModules").exists());
}

#[test]
fn extended_root_modules_export_their_text() {
    // An extension keeps only the root modules it extends, so they are not
    // the full set a configuration's root module group is recognised by.
    let input = common::fixture("extension_roots/modules/input.cfe");
    let out = common::temp_dir("extension-root-modules");
    let run = common::export(&input, &out);
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stdout)
    );
    for module in [
        "ManagedApplicationModule",
        "SessionModule",
        "ExternalConnectionModule",
        "OrdinaryApplicationModule",
    ] {
        let path = out.join(format!("Ext/{module}.bsl"));
        let text = fs::read_to_string(&path).unwrap_or_else(|_| panic!("{module} not exported"));
        assert!(text.contains(&format!("// {module}")), "{module}: {text}");
    }
}

#[test]
fn extension_config_dump_info_matches_the_platform() {
    // An extension keeps no `versions` entry; its `configinfo` lists every
    // entry with a SHA-1 whose hex is the `configVersion` the platform writes.
    let dir = common::fixture("test_extension");
    let out = common::temp_dir("extension-dump-info");
    let run = common::export(&dir.join("input.cfe"), &out);
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stdout)
    );
    let expected = fs::read(dir.join("expected/ConfigDumpInfo.xml")).unwrap();
    let actual = fs::read(out.join("ConfigDumpInfo.xml")).unwrap_or_default();
    assert!(
        expected == actual,
        "--- native\n{}\n--- ours\n{}",
        String::from_utf8_lossy(&expected),
        String::from_utf8_lossy(&actual)
    );
}

#[test]
fn a_degraded_extension_root_keeps_its_stored_compatibility() {
    // When the root writer degrades, the pipeline's Configuration.xml stays;
    // it printed the platform edition (Version8_3_27) as an extension's
    // compatibility, which only a configuration's is. `spellings` stores
    // 8.3.14 (`_onecdec/make_extension_degraded_fixture.py`).
    let input = common::fixture("extension_roots/unknown_property_compat14/input.cfe");
    let out = common::temp_dir("extension-unknown-compat14");
    let run = common::export(&input, &out);
    assert_eq!(run.status.code(), Some(2));
    let xml = fs::read_to_string(out.join("Configuration.xml")).unwrap();
    assert!(
        xml.contains(
            "<ConfigurationExtensionCompatibilityMode>Version8_3_14</ConfigurationExtensionCompatibilityMode>"
        ),
        "{xml}"
    );
}
