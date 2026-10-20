#![cfg(feature = "experimental-native-projection")]
use ibcmd_xml::dcs::reconcile_form_list_settings_data_parameters;

fn input(usage: &str, value: &str) -> String {
    format!("<dcsset:dataParameters>\r\n\t<dcscor:item xsi:type=\"dcsset:SettingsParameterValue\">\r\n\t\t<dcscor:use>{usage}</dcscor:use>\r\n\t\t<dcscor:parameter>P</dcscor:parameter>\r\n{value}\t</dcscor:item>\r\n</dcsset:dataParameters>\r\n")
}
fn state(restricted: bool, list: bool, default: &str) -> String {
    format!("<State xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"><Parameter><name>P</name><useRestriction>{restricted}</useRestriction><valueListAllowed>{list}</valueListAllowed>{default}</Parameter></State>")
}
const NIL: &str = "\t\t<dcscor:value xsi:nil=\"true\"/>\r\n";
const DEFAULT_NIL: &str = "<value xsi:nil=\"true\"/>";
fn project(usage: &str, value: &str, restricted: bool, list: bool, default: &str) -> String {
    reconcile_form_list_settings_data_parameters(&input(usage,value),Some(&state(restricted,list,default))).unwrap()
}
#[test] fn both_flags_disabled_nil_keeps_item_without_nil_value() { assert_eq!(project("false",NIL,true,true,DEFAULT_NIL),input("false","")); }
#[test] fn restricted_only_disabled_nil_still_omits_item() { assert_eq!(project("false",NIL,true,false,DEFAULT_NIL),"<dcsset:dataParameters/>\r\n"); }
#[test] fn allowed_only_disabled_nil_keeps_item_without_nil_value() { assert_eq!(project("false",NIL,false,true,DEFAULT_NIL),input("false","")); }
#[test] fn neither_flag_leaves_nil_exact() { assert_eq!(project("false",NIL,false,false,DEFAULT_NIL),input("false",NIL)); }
#[test] fn enabled_nil_does_not_drop_item() { assert_eq!(project("true",NIL,true,true,DEFAULT_NIL),input("true","")); }
#[test] fn explicit_non_nil_false_value_is_preserved() { let v="\t\t<dcscor:value xsi:type=\"xs:boolean\">false</dcscor:value>\r\n"; assert_eq!(project("false",v,true,true,DEFAULT_NIL),input("false",v)); }
#[test] fn absent_value_is_preserved() { assert_eq!(project("false","",true,true,DEFAULT_NIL),input("false","")); }
#[test] fn non_nil_or_absent_schema_default_does_not_trigger() { for d in ["", "<value>false</value>"] { assert_eq!(project("false",NIL,true,true,d),input("false",NIL)); } }
