# Remaining form binding limitation

The rights-order patch does not change form serialization.

A closed set of explicit roots from a query's `{SELECT ...}` extension is a
set in the data-composition domain. It does not establish the complete domain
of form-data bindings used by `UseAlways`. The platform documentation describes
different purposes for `DynamicList.AutoFillAvailableFields`, `DynamicList.Fields`
and a form attribute's `UseAlways` flag. In particular, MainTable has standard,
key and ordering fields with special rules. Equality of these domains is not a
documented premise of the current reader.

Conversely, the presence of a hierarchical MainTable does not establish that
every remembered standard-field binding is resolvable. Public native examples
include a marked IsFolder data path where the main table's reference is selected
under another name. Other examples explicitly select the field and export an
unmarked UseAlways entry. They do not settle the implicit-field case.
The marked MainTable/hierarchy example is an older XML 2.4 DataPath example;
it is not an attestation of XML 2.20 UseAlways behavior. A separate XML 2.20
UseAlways example has no MainTable, also different from the unresolved case.

We have not established a general rule for the last differing UseAlways marker.
The form code is therefore unchanged. Mapping an unproven absence to UNKNOWN
could repair the internal proof scope, but using the current plain-spelling
fallback would not, by itself, prove native serialization. We do not remove
the marker merely to match a control export.

This remains a native XML limitation, separate from available BSL extraction.
There is no platform execution or reconstruction of closed source code.
