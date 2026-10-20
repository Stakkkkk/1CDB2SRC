//! Managed-form code that depends on the platform build or on the XML format.
//!
//! Modules here are named after the FULL version in which their subject first
//! appeared, never after a family nickname such as "85":
//!
//! - `layout_<platform>`: a stored form-body layout that platform introduced
//!   (`layout_8_5_1`: root revision 59 and the members 8.5.1 appends to the
//!   8.3 records), read by down-converting it to the previous layout;
//! - `load_<platform>`: compiling a `Form.xml` into that layout;
//! - `xml_<format>_*`: code of one XML dialect, named by the XML format
//!   version (`xml_2_21_writer`, `xml_2_21_order`: what the 2.21 `Form.xml`
//!   adds to the 2.20 one).
//!
//! Which layout and which XML format a build uses is the platform registry's
//! answer (`src/platform/`), not something to infer from a version number.
//! When a new build arrives (say 8.5.4):
//!
//! - nothing changed in its forms: one registry entry, no code here;
//! - its stored layout changed: a delta module `layout_8_5_4.rs` (and
//!   `load_8_5_4.rs`) converting between it and the 8.5.1 layout, chosen by
//!   the registry's `form_layout()`;
//! - its XML format changed (say to 2.22): `xml_2_22_*` modules beside the
//!   2.21 ones, chosen by the registry's `xml_version()`.

pub(super) mod layout_8_5_1;
pub(super) mod load_8_5_1;
pub(super) mod xml_2_21_order;
pub(super) mod xml_2_21_writer;
