use std::collections::{BTreeMap, BTreeSet};
use ibcmd_xml::rewrite_dcs_primary_schema_storage_document;

fn rewrite(value: &str, references: BTreeMap<String, String>) -> Result<String, String> {
    rewrite_with_attributes(value, "", references)
}

fn rewrite_with_attributes(value: &str, attributes: &str, references: BTreeMap<String, String>) -> Result<String, String> {
    let body = format!(r#"<SchemaFile xmlns="" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dataCompositionSchema xmlns="http://v8.1c.ru/8.1/data-composition-system/schema">
    <parameter><name>P</name><valueType xmlns:v8="http://v8.1c.ru/8.1/data/core"><v8:TypeId{attributes}>{value}</v8:TypeId></valueType></parameter>
  </dataCompositionSchema>
</SchemaFile>"#);
    let xml = format!("\u{feff}<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n{}", body.replace('\n', "\r\n"));
    rewrite_dcs_primary_schema_storage_document(xml.as_bytes(), &references,
        &BTreeMap::new(), &BTreeSet::new(), &BTreeMap::new(), &[])
        .map(|data| String::from_utf8(data).unwrap()).map_err(|error| error.to_string())
}

#[test]
fn preserves_unbound_uuid_lexeme_without_inventing_a_name() {
    for value in ["f0000000-0000-0000-0000-000000000001", "F0000000-0000-0000-0000-000000000001"] {
        let xml = rewrite(value, BTreeMap::new()).unwrap();
        assert!(xml.contains(&format!("<v8:TypeId>{value}</v8:TypeId>")));
    }
}

#[test]
fn known_reference_resolution_still_wins() {
    let value = "f0000000-0000-0000-0000-000000000001";
    let xml = rewrite(value, BTreeMap::from([(value.to_owned(), "CatalogRef.Example".to_owned())])).unwrap();
    assert!(xml.contains(":CatalogRef.Example</v8:Type>"));
    assert!(!xml.contains("<v8:TypeId>"));
}

#[test]
fn refuses_malformed_or_non_uuid_type_id() {
    for value in ["", "arbitrary-name", "f00000000000000000000000000000000001",
                  "g0000000-0000-0000-0000-000000000001", "f0000000_0000-0000-0000-000000000001"] {
        assert!(rewrite(value, BTreeMap::new()).is_err(), "accepted {value:?}");
    }
}

#[test]
fn refuses_children_or_non_namespace_attributes_on_unbound_type_id() {
    assert!(rewrite("f0000000-0000-0000-0000-000000000001<v8:Type>xs:string</v8:Type>tail", BTreeMap::new()).is_err());
    assert!(rewrite_with_attributes("f0000000-0000-0000-0000-000000000001", " bad=\"1\"", BTreeMap::new()).is_err());
}
