//! Hermetic compiler -> physical storage reader checks, no lab fixtures/platform.
use std::{collections::BTreeMap, fs, io::Write, path::PathBuf};
use flate2::{Compression, write::DeflateEncoder};
use ibcmd_rs::{cli::InfobaseConfigSourceVersion as Version, metadata_model::{DescriptorContext, compile_descriptor, brace::{Brace, parse_row, serialize_row}}, mssql_dump::{ForeignReferences, export_packed_entries_to_source}};

const ROOT: &str = "10000000-0000-4000-8000-000000000456";
struct Temp(PathBuf);
impl Temp { fn new() -> Self { let p=std::env::temp_dir().join(format!("configuration-legacy-{}",uuid::Uuid::new_v4()));fs::create_dir(&p).unwrap();Self(p) } }
impl Drop for Temp { fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); } }
fn fixture(purposes: &[&str]) -> (Temp, Brace) {
    let temp=Temp::new();
    let classes=["9cd510cd-abfc-11d4-9434-004095e12fc7","9fcd25a0-4822-11d4-9414-008048da11f9","e3687481-0a87-462c-a166-9f34594f9bba","9de14907-ec23-4a07-96f0-85521cb6b53b","51f2d5d8-ea4d-4064-8892-82951750031e","e68182ea-4237-4383-967f-90c1e3370bc7","fb282519-d103-4dd3-bc12-cb271d631dfc"];
    let info=classes.iter().enumerate().map(|(i,c)|format!("<xr:ContainedObject><xr:ClassId>{c}</xr:ClassId><xr:ObjectId>20000000-0000-4000-8000-{:012}</xr:ObjectId></xr:ContainedObject>",i+1)).collect::<String>();
    let purposes=purposes.iter().map(|p|format!("<v8:Value xsi:type=\"app:ApplicationUsePurpose\">{p}</v8:Value>")).collect::<String>();
    let xml=format!("<MetaDataObject xmlns=\"http://v8.1c.ru/8.3/MDClasses\" xmlns:xr=\"http://v8.1c.ru/8.3/xcf/readable\" xmlns:v8=\"http://v8.1c.ru/8.1/data/core\" xmlns:app=\"http://v8.1c.ru/8.2/managed-application/core\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" version=\"2.20\"><Configuration uuid=\"{ROOT}\"><InternalInfo>{info}</InternalInfo><Properties><Name>NeutralLegacy</Name><Synonym/><Comment/><DefaultRunMode>ManagedApplication</DefaultRunMode><ScriptVariant>Russian</ScriptVariant><CompatibilityMode>Version8_3_24</CompatibilityMode><InterfaceCompatibilityMode>Taxi</InterfaceCompatibilityMode><UsePurposes>{purposes}</UsePurposes></Properties><ChildObjects/></Configuration></MetaDataObject>");
    let path=temp.0.join("Configuration.xml");fs::write(&path,&xml).unwrap();let files=vec![(path.clone(),std::sync::Arc::new(xml.as_bytes().to_vec()))];let context=DescriptorContext::with_files(&temp.0,"2.20",&files).unwrap();let row=compile_descriptor("Configuration",&path,xml.as_bytes(),&context).unwrap();(temp,parse_row(&row).unwrap())
}
fn fields(row:&mut Brace)->&mut Vec<Brace>{ row.as_list_mut().unwrap()[3].as_list_mut().unwrap()[1].as_list_mut().unwrap()[1].as_list_mut().unwrap() }
fn export(row:&Brace, version:Version)->(Temp,Option<String>){
    let temp=Temp::new();let mut deflater=DeflateEncoder::new(Vec::new(),Compression::default());deflater.write_all(&serialize_row(row)).unwrap();let data=deflater.finish().unwrap();
    let report=export_packed_entries_to_source("test:neutral-legacy",vec![(ROOT.to_owned(),data)],&temp.0,false,version,Some(&ForeignReferences{objects:BTreeMap::new(),types:vec![]})).unwrap();assert_eq!(report.storage.failed,0,"{report:?}");let xml=fs::read_to_string(temp.0.join("Configuration.xml")).ok();(temp,xml)
}
#[test]
fn legacy_modes_independent_and_all_purposes_preserved_in_both_writers(){
    for purposes in [vec!["PlatformApplication"],vec!["MobilePlatformApplication"],vec!["PlatformApplication","MobilePlatformApplication"],vec!["MobilePlatformApplication","PlatformApplication"]] {
        let (_source,mut row)=fixture(&purposes);fields(&mut row)[43]=Brace::num(80317);
        for (version,reader) in [(Version::V2_20,"Version8_3_27"),(Version::V2_21,"Version8_5_1")] {
            let (_out,xml)=export(&row,version);let xml=xml.expect("root must be written");assert!(xml.contains("<CompatibilityMode>Version8_3_24</CompatibilityMode>"));assert!(xml.contains(&format!("<ConfigurationExtensionCompatibilityMode>{reader}</ConfigurationExtensionCompatibilityMode>")));
            let mut last=0;for p in &purposes { let token=format!(">{p}</v8:Value>");let pos=xml.find(&token).unwrap();assert!(pos>last);last=pos; }
            assert_eq!(xml.matches("xsi:type=\"app:ApplicationUsePurpose\"").count(),purposes.len());
        }
    }
}
#[test]
fn bad_typed_purpose_does_not_disappear_from_an_accepted_root(){
    let (_source,mut row)=fixture(&["PlatformApplication"]);fields(&mut row)[33]=Brace::List(vec![Brace::num(1),Brace::List(vec![Brace::str("#"),Brace::uuid("1708fdaa-cbce-4289-b373-07a5a74bee91"),Brace::num(3)])]);
    let (_out,xml)=export(&row,Version::V2_20);assert!(xml.is_none(),"unknown purpose must refuse root, not drop the property");
}
