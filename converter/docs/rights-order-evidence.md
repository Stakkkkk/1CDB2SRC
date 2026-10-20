# Native top-level Rights.xml order

The object-right order table is based on independent public Designer exports,
not on the ERP expected output, the input CF's incidental sequence, the order of
UUID lookup tables, or EDT's different format.

Source: [1c-syntax/mdclasses](https://github.com/1c-syntax/mdclasses), commit
`ea69cc0c076f51a2a6050bbc2171eeeb018ec8be`:

- `src/test/resources/ext/designer/mdclasses_3_25/src/cf/Roles/{Роль1,Роль2}/Ext/Rights.xml`
- `src/test/resources/ext/designer/mdclasses_3_27/src/cf/Roles/{Роль1,Роль2}/Ext/Rights.xml`

The four files contain matching relative orders for top-level Catalog and
InformationRegister records (including partial lists). The public 3_27
[Role1 fixture](https://github.com/1c-syntax/mdclasses/blob/ea69cc0c076f51a2a6050bbc2171eeeb018ec8be/src/test/resources/ext/designer/mdclasses_3_27/src/cf/Roles/Роль1/Ext/Rights.xml)
is XML 2.20; the 3_25 fixture is XML 2.18. These observations support a schema
order for those two families, not a claim about all platform releases or all
metadata kinds. No public XML file is shipped as a production template.

The renderer sorts the records **after** the existing presence/default and
restriction decisions. The table never adds, drops or changes a right, value,
restriction or object. Names of user roles and metadata objects are irrelevant.
Nested objects, other kinds and lists containing an unknown right keep their
original order. Duplicate entries retain multiplicity and stable relative order.

Standalone focused tests, requiring only Rust and no external fixtures:

```sh
rustc --edition=2024 --test crates/ibcmd-schema/src/object_rights.rs -o /tmp/object-rights-tests
/tmp/object-rights-tests
```

This tests the actual schema module. A production build and CF-to-XML checks
are separate validation steps; passing these unit tests alone does not establish
that a complete export matches the platform output.
