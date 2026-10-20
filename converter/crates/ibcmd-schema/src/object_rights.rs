//! Native Rights.xml order for the two evidenced top-level object families.
//!
//! Independent evidence (not the ERP control tree): 1c-syntax/mdclasses,
//! ea69cc0c076f51a2a6050bbc2171eeeb018ec8be, public Designer fixtures
//! `mdclasses_3_25` (XML 2.18) and `mdclasses_3_27` (XML 2.20),
//! `src/cf/Roles/{Роль1,Роль2}/Ext/Rights.xml`. Full and partial lists agree.
//! These are observations of native export, not an EDT order contract.
//! See docs/rights-order-evidence.md in the converter source tree.

pub const CATALOG_RIGHT_ORDER: &[&str] = &[
    "Read", "Insert", "Update", "Delete", "View", "InteractiveInsert", "Edit",
    "InteractiveDelete", "InteractiveSetDeletionMark", "InteractiveClearDeletionMark",
    "InteractiveDeleteMarked", "InputByString", "InteractiveDeletePredefinedData",
    "InteractiveSetDeletionMarkPredefinedData", "InteractiveClearDeletionMarkPredefinedData",
    "InteractiveDeleteMarkedPredefinedData", "ReadDataHistory", "ReadDataHistoryOfMissingData",
    "UpdateDataHistory", "UpdateDataHistoryOfMissingData", "UpdateDataHistorySettings",
    "UpdateDataHistoryVersionComment", "ViewDataHistory", "EditDataHistoryVersionComment",
    "SwitchToDataHistoryVersion",
];

pub const INFORMATION_REGISTER_RIGHT_ORDER: &[&str] = &[
    "Read", "Update", "View", "Edit", "TotalsControl", "ReadDataHistory",
    "ReadDataHistoryOfMissingData", "UpdateDataHistory", "UpdateDataHistoryOfMissingData",
    "UpdateDataHistorySettings", "UpdateDataHistoryVersionComment", "ViewDataHistory",
    "EditDataHistoryVersionComment", "SwitchToDataHistoryVersion",
];

/// Reorder existing, already-filtered records without changing their contents.
/// Unknown rights, unknown kinds, and nested objects retain their input order.
/// No rights are added and no values, restrictions or object order are inferred.
/// Returns whether the complete list belongs to an evidenced family.
pub fn order_native_object_rights<T>(
    object_name: &str,
    rights: &mut [T],
    name: impl Fn(&T) -> &str,
) -> bool {
    let Some((kind, object)) = object_name.split_once('.') else {
        return false;
    };
    if object.is_empty() || object.contains('.') {
        return false;
    }
    let order = match kind {
        "Catalog" => CATALOG_RIGHT_ORDER,
        "InformationRegister" => INFORMATION_REGISTER_RIGHT_ORDER,
        _ => return false,
    };
    if rights.iter().any(|right| !order.contains(&name(right))) {
        return false;
    }
    rights.sort_by_key(|right| order.iter().position(|known| *known == name(right)));
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Right {
        name: &'static str,
        value: bool,
        restrictions: Vec<&'static str>,
    }

    #[test]
    fn arbitrary_catalog_name_and_permutation_restore_native_order() {
        let mut rights = CATALOG_RIGHT_ORDER.iter().rev().copied().collect::<Vec<_>>();
        assert!(order_native_object_rights("Catalog.UnrelatedName", &mut rights, |r| *r));
        assert_eq!(rights, CATALOG_RIGHT_ORDER);
    }

    #[test]
    fn register_totals_and_history_are_independent_of_input_positions() {
        let mut rights = vec!["ViewDataHistory", "UpdateDataHistorySettings", "TotalsControl", "Read"];
        assert!(order_native_object_rights("InformationRegister.Example", &mut rights, |r| *r));
        assert_eq!(rights, ["Read", "TotalsControl", "UpdateDataHistorySettings", "ViewDataHistory"]);
    }

    #[test]
    fn all_rotations_and_subsets_keep_values_and_restrictions() {
        for (kind, order) in [("Catalog", CATALOG_RIGHT_ORDER), ("InformationRegister", INFORMATION_REGISTER_RIGHT_ORDER)] {
            let all = order.iter().enumerate().map(|(i, name)| Right {
                name, value: i % 2 == 0, restrictions: vec!["WHERE Allowed", "Field.Name"],
            }).collect::<Vec<_>>();
            for shift in 0..all.len() {
                for step in 1..=4 {
                    let expected = all.iter().enumerate().filter(|(i, _)| i % step == 0).map(|(_, r)| r.clone()).collect::<Vec<_>>();
                    let mut input = all.clone();
                    input.rotate_left(shift);
                    input.retain(|r| expected.contains(r));
                    assert!(order_native_object_rights(&format!("{kind}.Renamed"), &mut input, |r| r.name));
                    assert_eq!(input, expected);
                }
            }
        }
    }

    #[test]
    fn nested_objects_other_types_and_unknown_rights_are_unchanged() {
        for object in ["Catalog.A.Attribute.B", "Catalog.A.Command.B", "Configuration.A", "Document.A", "Catalog.", "Catalog"] {
            let mut rights = vec!["Edit", "Read"];
            assert!(!order_native_object_rights(object, &mut rights, |r| *r));
            assert_eq!(rights, ["Edit", "Read"]);
        }
        let mut rights = vec!["ViewDataHistory", "FutureRight", "Read"];
        assert!(!order_native_object_rights("Catalog.Other", &mut rights, |r| *r));
        assert_eq!(rights, ["ViewDataHistory", "FutureRight", "Read"]);
    }

    #[test]
    fn empty_single_and_duplicate_records_preserve_multiplicity_and_stability() {
        let mut empty: Vec<&str> = vec![];
        assert!(order_native_object_rights("Catalog.A", &mut empty, |r| *r));
        let mut one = vec!["Edit"];
        assert!(order_native_object_rights("Catalog.A", &mut one, |r| *r));
        assert_eq!(one, ["Edit"]);
        let mut rights = vec![("Edit", 1), ("Read", 2), ("Edit", 3)];
        assert!(order_native_object_rights("Catalog.A", &mut rights, |r| r.0));
        assert_eq!(rights, [("Read", 2), ("Edit", 1), ("Edit", 3)]);
    }
}
