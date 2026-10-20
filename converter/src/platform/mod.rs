//! The platform registry: every 1C:Enterprise build ibcmd-rs knows, and what
//! each one implies for the XML it reads and writes and for the rows it
//! stores.
//!
//! One place answers "what does platform X do":
//!
//! - its XML format: 8.3.x reads and writes 2.20, 8.5.x 2.21
//!   ([`PlatformSpec::xml_version`]);
//! - the stored layout of its managed forms and of the colours and fonts of
//!   other rows: the 8.3 one, or the one 8.5.1 introduced
//!   ([`PlatformSpec::form_layout`]);
//! - the features a configuration saved by it may list in its `version` row,
//!   such as the 8.5.1 palette colours ([`PlatformSpec::features`]);
//! - whether direct MSSQL activation is evidenced for it
//!   ([`PlatformSpec::live_activation`]).
//!
//! The builds and what they declare live in `profiles/platform/*.json`: the
//! bundled profiles `profile_registry` compiles in, whose MSSQL write
//! capabilities `MssqlNativePlatformProfile` checks. This module reads the
//! same declarations -- the constants `platform.xml_format`,
//! `platform.form_layout` and `platform.feature.<name>` -- instead of
//! repeating them in code. A build whose profile declares no XML format (the
//! 8.3.24.1819 seed) is known but not supported.
//!
//! A platform is named by its full version: an exact build (`8.3.27.2214`)
//! or a release (`8.3.27`), which stands for every known build of it and
//! exists only while they agree on what they declare. A version the registry
//! does not know is refused with the list of known ones, never mapped to the
//! nearest one.
//!
//! # Naming, and what a new build needs
//!
//! Code that depends on the platform is named after the FULL version in which
//! its subject first appeared -- `mssql_dump/form/layout_8_5_1.rs`,
//! `FormFactsV8_5_1`, [`FormLayout::V8_5_1`] -- and code of an XML dialect
//! after the XML format (`mssql_dump/form/xml_2_21_writer.rs`), never after a
//! nickname such as "85". When a new build arrives, say 8.5.4:
//!
//! - nothing changed for ibcmd-rs: one registry entry,
//!   `profiles/platform/8.5.4.<build>.json` listed in
//!   `profile_registry::BUNDLED_PROFILES`, declaring the XML format, form
//!   layout and features it shares with 8.5.1;
//! - its stored layout changed: in addition a delta module
//!   `mssql_dump/form/layout_8_5_4.rs` (and `load_8_5_4.rs`) converting
//!   between it and the 8.5.1 layout, a `FormLayout::V8_5_4`, and the entry
//!   declares `"platform.form_layout": "8.5.4"`;
//! - its XML format changed (say to 2.22): `xml_2_22_*` modules, an
//!   `InfobaseConfigSourceVersion::V2_22`, and the entry declares
//!   `"platform.xml_format": "2.22"`.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::OnceLock;

use anyhow::{Context, Result, anyhow, bail};
use clap::ValueEnum;
use ibcmd_core::profile::{CapabilityId, CapabilityState, EffectiveProfile};
use serde::{Serialize, Serializer};

use crate::legacy_version::InfobaseConfigSourceVersion;
use crate::mssql_platform_profile::{CAPABILITY_MAIN_WRITE, MssqlNativePlatformProfile};

/// Profile constant: the XML format a build reads and writes (`2.20`, `2.21`).
pub const CONSTANT_XML_FORMAT: &str = "platform.xml_format";
/// Profile constant: the stored form layout of a build (`8.3`, `8.5.1`).
pub const CONSTANT_FORM_LAYOUT: &str = "platform.form_layout";
/// Profile constant prefix: `platform.feature.<name>` = the feature's uuid.
pub const CONSTANT_FEATURE_PREFIX: &str = "platform.feature.";
/// Profile constant: `main` when the build writes `ButtonImportance` `Main`
/// on a default button whose record holds the code of no importance of its
/// own (8.5.1.1529; 8.5.1.1150 writes nothing there).
pub const CONSTANT_DEFAULT_BUTTON_IMPORTANCE: &str = "platform.form.default_button_importance";
/// The palette-colours feature (since 8.5.1): every `PaletteColor` object a
/// configuration holds reports it, and its `version` row lists it.
pub const FEATURE_PALETTE_COLORS: &str = "palette-colors";

/// Help text of the `--platform` flag.
pub const PLATFORM_FLAG_HELP: &str = "Platform the XML is for: a release (8.3.27, 8.5.1) or an exact build (8.3.27.2214, 8.5.1.1150); 8.3.x reads and writes XML 2.20, 8.5.x 2.21";

/// The stored layout of managed-form bodies, and of the colours and fonts in
/// the other rows of a configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum FormLayout {
    /// The layout 8.3 platforms store: form root revision 50, colours
    /// `{3,...}`, fonts `{7,...}`.
    #[serde(rename = "8.3")]
    V8_3,
    /// The layout 8.5.1 introduced: form root revision 59, members appended
    /// to the 8.3 records, colours `{4,...}`, fonts `{8,...}`.
    #[serde(rename = "8.5.1")]
    V8_5_1,
}

impl FormLayout {
    /// The version that introduced the layout, as profiles declare it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::V8_3 => "8.3",
            Self::V8_5_1 => "8.5.1",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "8.3" => Some(Self::V8_3),
            "8.5.1" => Some(Self::V8_5_1),
            _ => None,
        }
    }

    /// The layout a configuration's rows take on a platform whose own layout
    /// is `self`: a configuration kept in a compatibility mode older than 8.5
    /// (packed, `80327`) keeps the 8.3 layout -- every form and style of the
    /// ERP УХ 8.5 clone, compatibility 8.3.27, is stored the 8.3 way -- while
    /// compatibility 8.5 or later takes the platform's own.
    pub fn stored(self, compatibility: u32) -> Self {
        if compatibility >= 80500 {
            self
        } else {
            Self::V8_3
        }
    }
}

impl fmt::Display for FormLayout {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A feature a configuration saved by the platform can list in its
/// `version` row, which an older platform that does not know it refuses.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct PlatformFeature {
    name: String,
    uuid: String,
}

impl PlatformFeature {
    /// The feature's name in the profiles (`palette-colors`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The fixed uuid the platform's feature registry gives it.
    pub fn uuid(&self) -> &str {
        &self.uuid
    }
}

/// One known build, or one release standing for its builds.
#[derive(Debug, PartialEq, Eq)]
struct Entry {
    /// `8.3.27.2214` or `8.3.27`.
    name: String,
    release: [u32; 3],
    /// The fourth component of an exact build.
    build: Option<u32>,
    xml: InfobaseConfigSourceVersion,
    form_layout: FormLayout,
    features: Vec<PlatformFeature>,
    native_profile: Option<MssqlNativePlatformProfile>,
    live_activation: bool,
    /// See [`CONSTANT_DEFAULT_BUTTON_IMPORTANCE`]. A release never has it: it
    /// stands for the builds that agree on the XML format, the form layout and
    /// the features, and keeps the behavior of the oldest of them.
    default_button_importance: bool,
}

#[derive(Debug)]
struct Registry {
    /// Exact builds, then releases, each in version order.
    entries: Vec<Entry>,
    /// Builds a profile names without declaring an XML format.
    unsupported: Vec<String>,
    /// Releases whose builds disagree, so only a build names them.
    ambiguous_releases: Vec<String>,
}

static REGISTRY: OnceLock<std::result::Result<Registry, String>> = OnceLock::new();

fn registry() -> Result<&'static Registry> {
    REGISTRY
        .get_or_init(|| build_registry().map_err(|error| format!("{error:#}")))
        .as_ref()
        .map_err(|error| anyhow!("the bundled platform registry is invalid: {error}"))
}

fn build_registry() -> Result<Registry> {
    let profiles = crate::profile_registry::load_bundled_profile_registry()?;
    let mut builds = Vec::new();
    let mut unsupported = Vec::new();
    for profile in profiles.profiles().values() {
        let Some(build) = &profile.platform_build else {
            continue;
        };
        let name = build.value.to_string();
        let components = build.value.as_version().components();
        let &[major, minor, patch, number] = components else {
            bail!(
                "platform profile `{}` names `{name}`, not a four-part build",
                profile.id
            );
        };
        match build_entry(profile, name.clone(), [major, minor, patch], number)? {
            Some(entry) => builds.push(entry),
            None => unsupported.push(name),
        }
    }
    builds.sort_by_key(|entry| (entry.release, entry.build));

    let mut by_release = BTreeMap::<[u32; 3], Vec<&Entry>>::new();
    for entry in &builds {
        by_release.entry(entry.release).or_default().push(entry);
    }
    let mut releases = Vec::new();
    let mut ambiguous_releases = Vec::new();
    for (release, members) in by_release {
        let first = members[0];
        let agree = members.iter().all(|entry| {
            entry.xml == first.xml
                && entry.form_layout == first.form_layout
                && entry.features == first.features
        });
        let name = release_name(release);
        if !agree {
            ambiguous_releases.push(name);
            continue;
        }
        releases.push(Entry {
            name,
            release,
            build: None,
            xml: first.xml,
            form_layout: first.form_layout,
            features: first.features.clone(),
            native_profile: None,
            live_activation: false,
            default_button_importance: false,
        });
    }
    let mut entries = builds;
    entries.extend(releases);
    Ok(Registry {
        entries,
        unsupported,
        ambiguous_releases,
    })
}

/// A build entry from its profile, or `None` when the profile declares no
/// XML format (a build ibcmd-rs does not read or write).
fn build_entry(
    profile: &EffectiveProfile,
    name: String,
    release: [u32; 3],
    build: u32,
) -> Result<Option<Entry>> {
    let constant = |key: &str| profile.constants.get(key).map(|value| value.value.as_str());
    let Some(xml) = constant(CONSTANT_XML_FORMAT) else {
        return Ok(None);
    };
    let xml = match xml {
        "2.20" => InfobaseConfigSourceVersion::V2_20,
        "2.21" => InfobaseConfigSourceVersion::V2_21,
        other => bail!(
            "platform profile `{}` declares {CONSTANT_XML_FORMAT} `{other}`, which ibcmd-rs does not read or write",
            profile.id
        ),
    };
    let layout = constant(CONSTANT_FORM_LAYOUT).ok_or_else(|| {
        anyhow!(
            "platform profile `{}` declares its XML format but no {CONSTANT_FORM_LAYOUT}",
            profile.id
        )
    })?;
    let form_layout = FormLayout::parse(layout).ok_or_else(|| {
        anyhow!(
            "platform profile `{}` declares an unknown {CONSTANT_FORM_LAYOUT} `{layout}`",
            profile.id
        )
    })?;
    let mut features = Vec::new();
    for (key, value) in &profile.constants {
        let Some(feature) = key.strip_prefix(CONSTANT_FEATURE_PREFIX) else {
            continue;
        };
        let uuid = uuid::Uuid::parse_str(&value.value).with_context(|| {
            format!(
                "platform profile `{}` declares feature `{feature}` with a malformed uuid",
                profile.id
            )
        })?;
        features.push(PlatformFeature {
            name: feature.to_string(),
            uuid: uuid.hyphenated().to_string(),
        });
    }
    features.sort();
    let native_profile = MssqlNativePlatformProfile::value_variants()
        .iter()
        .copied()
        .find(|native| native.id() == profile.id.as_str());
    let main_write = CapabilityId::parse(CAPABILITY_MAIN_WRITE)
        .map_err(|error| anyhow!("invalid capability id `{CAPABILITY_MAIN_WRITE}`: {error}"))?;
    let live_activation = profile
        .capabilities
        .get(&main_write)
        .is_some_and(|state| state.value == CapabilityState::Supported);
    let default_button_importance = match constant(CONSTANT_DEFAULT_BUTTON_IMPORTANCE) {
        None => false,
        Some("main") => true,
        Some(other) => bail!(
            "platform profile `{}` declares an unknown {CONSTANT_DEFAULT_BUTTON_IMPORTANCE} `{other}`",
            profile.id
        ),
    };
    Ok(Some(Entry {
        name,
        release,
        build: Some(build),
        xml,
        form_layout,
        features,
        native_profile,
        live_activation,
        default_button_importance,
    }))
}

fn release_name(release: [u32; 3]) -> String {
    format!("{}.{}.{}", release[0], release[1], release[2])
}

/// A known platform: an exact build or a release.
///
/// Cheap to copy; two specs are equal when they name the same entry.
#[derive(Clone, Copy)]
pub struct PlatformSpec {
    entry: &'static Entry,
}

impl PartialEq for PlatformSpec {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self.entry, other.entry)
    }
}

impl Eq for PlatformSpec {}

impl fmt::Debug for PlatformSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PlatformSpec")
            .field(&self.entry.name)
            .finish()
    }
}

impl fmt::Display for PlatformSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.entry.name)
    }
}

impl Serialize for PlatformSpec {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.entry.name)
    }
}

impl PlatformSpec {
    /// The XML format the platform reads and writes: 2.20 for 8.3.x, 2.21 for
    /// 8.5.x.
    pub fn xml_version(&self) -> InfobaseConfigSourceVersion {
        self.entry.xml
    }

    /// The platform's own stored layout of forms, colours and fonts; a
    /// configuration kept in an older compatibility mode may store the
    /// previous one ([`FormLayout::stored`]).
    pub fn form_layout(&self) -> FormLayout {
        self.entry.form_layout
    }

    /// The features beyond older platforms' that the platform knows, by name.
    pub fn features(&self) -> &'static [PlatformFeature] {
        &self.entry.features
    }

    /// One feature by name, when the platform knows it.
    pub fn feature(&self, name: &str) -> Option<&'static PlatformFeature> {
        self.entry
            .features
            .iter()
            .find(|feature| feature.name == name)
    }

    /// The version as given: `8.5.1.1150` or `8.5.1`.
    pub fn display(&self) -> &'static str {
        &self.entry.name
    }

    /// Whether the spec names one exact build rather than a release.
    pub fn is_exact_build(&self) -> bool {
        self.entry.build.is_some()
    }

    /// `[8, 5, 1]`: the release, also the compatibility mode the platform
    /// runs a configuration in that names none.
    pub fn release(&self) -> [u32; 3] {
        self.entry.release
    }

    /// The release as a spec (itself for a release).
    pub fn release_spec(&self) -> Result<PlatformSpec> {
        if self.entry.build.is_none() {
            return Ok(*self);
        }
        parse(&release_name(self.entry.release))
    }

    /// The platform's own compatibility level, packed as the rows store it:
    /// `80327`, `80501`.
    pub fn compatibility_packed(&self) -> u32 {
        let [major, minor, patch] = self.entry.release;
        major * 10000 + minor * 100 + patch
    }

    /// The platform's own compatibility mode as `Configuration.xml` spells
    /// it: `Version8_3_27`, `Version8_5_1`.
    pub fn compatibility_mode(&self) -> String {
        let [major, minor, patch] = self.entry.release;
        format!("Version{major}_{minor}_{patch}")
    }

    /// Whether the build writes `ButtonImportance` `Main` on a default button
    /// whose record holds the code of no importance of its own (see
    /// [`CONSTANT_DEFAULT_BUTTON_IMPORTANCE`]).
    pub fn writes_default_button_importance(&self) -> bool {
        self.entry.default_button_importance
    }

    /// The native MSSQL profile of an exact build, when one is declared.
    pub fn native_profile(&self) -> Option<MssqlNativePlatformProfile> {
        self.entry.native_profile
    }

    /// Whether direct MSSQL activation of a staged configuration (without
    /// native ibcmd) is evidenced for this exact build: its profile declares
    /// `mssql.main.write` supported. A release is never enough, because the
    /// activation verifies the exact build it talks to.
    pub fn live_activation(&self) -> bool {
        self.entry.live_activation
    }
}

static EXPORT_DEFAULT_BUTTON_IMPORTANCE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Records the platform an export command runs for, once, at its start: the
/// writers of the XML spell a few things by the build (the XML format alone
/// does not tell 8.5.1.1150 from 8.5.1.1529). With no platform named, or a
/// release, the export keeps the spelling of the oldest build the registry
/// knows for the format.
pub fn note_export_platform(platform: PlatformSpec) {
    EXPORT_DEFAULT_BUTTON_IMPORTANCE.store(
        platform.writes_default_button_importance(),
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// See [`PlatformSpec::writes_default_button_importance`], for the platform
/// [`note_export_platform`] recorded.
pub fn export_writes_default_button_importance() -> bool {
    EXPORT_DEFAULT_BUTTON_IMPORTANCE.load(std::sync::atomic::Ordering::Relaxed)
}

/// Parses a platform version: an exact build (`8.3.27.2214`) or a release
/// (`8.3.27`) the registry knows.
pub fn parse(text: &str) -> Result<PlatformSpec> {
    let text = text.trim();
    let registry = registry()?;
    let components = text
        .split('.')
        .map(|part| {
            (!part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
                .then(|| part.parse::<u32>().ok())
                .flatten()
        })
        .collect::<Option<Vec<_>>>();
    let Some(components) = components.filter(|parts| matches!(parts.len(), 3 | 4)) else {
        bail!(
            "`{text}` is not a platform version: name a release such as 8.3.27 or an exact build such as 8.3.27.2214 ({})",
            known_list(registry)
        );
    };
    let canonical = components
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(".");
    if let Some(entry) = registry
        .entries
        .iter()
        .find(|entry| entry.name == canonical)
    {
        return Ok(PlatformSpec { entry });
    }
    if registry.unsupported.contains(&canonical) {
        bail!(
            "platform {canonical} is not supported: ibcmd-rs reads and writes only the XML of the platforms it knows ({})",
            known_list(registry)
        );
    }
    if registry.ambiguous_releases.contains(&canonical) {
        bail!(
            "the known builds of {canonical} differ in their XML format, form layout or features: name the exact build ({})",
            known_list(registry)
        );
    }
    let what = if components.len() == 4 {
        "build"
    } else {
        "release"
    };
    bail!(
        "unknown platform {what} {canonical}: ibcmd-rs knows {}",
        known_list(registry)
    )
}

/// The release that reads and writes an XML format: 2.20 -> 8.3.27, 2.21 ->
/// 8.5.1. A format no known release writes, or one several releases write,
/// is refused: only a platform named outright tells them apart.
pub fn for_xml_version(xml: InfobaseConfigSourceVersion) -> Result<PlatformSpec> {
    let registry = registry()?;
    let mut releases = registry
        .entries
        .iter()
        .filter(|entry| entry.build.is_none() && entry.xml == xml);
    match (releases.next(), releases.next()) {
        (Some(entry), None) => Ok(PlatformSpec { entry }),
        (None, _) => bail!(
            "no known platform writes XML {}: ibcmd-rs knows {}",
            xml.as_str(),
            known_list(registry)
        ),
        (Some(first), Some(second)) => bail!(
            "XML {} is written by more than one known release ({}, {}, ...): name the platform",
            xml.as_str(),
            first.name,
            second.name
        ),
    }
}

/// The release of an XML dialect as the metadata contexts carry it: `2.20`
/// is 8.3.27's and any other dialect 8.5.1's, the way their
/// `is_xml_2_21()` reads it.
///
/// # Panics
///
/// Only when the bundled registry lacks the 8.3.27 or the 8.5.1 release,
/// which its tests rule out.
pub(crate) fn of_xml_dialect(dialect: &str) -> PlatformSpec {
    let xml = if dialect == InfobaseConfigSourceVersion::V2_20.as_str() {
        InfobaseConfigSourceVersion::V2_20
    } else {
        InfobaseConfigSourceVersion::V2_21
    };
    for_xml_version(xml).expect("the bundled platform registry maps XML 2.20 and 2.21")
}

/// Every known build and release, builds first, each in version order.
pub fn known() -> Result<Vec<PlatformSpec>> {
    Ok(registry()?
        .entries
        .iter()
        .map(|entry| PlatformSpec { entry })
        .collect())
}

/// The uuid of a named feature, as the builds that know it declare it.
pub fn feature_uuid(name: &str) -> Result<&'static str> {
    registry()?
        .entries
        .iter()
        .flat_map(|entry| &entry.features)
        .find(|feature| feature.name == name)
        .map(|feature| feature.uuid.as_str())
        .ok_or_else(|| anyhow!("no known platform declares the feature `{name}`"))
}

/// For clap: parses `--platform` through the registry.
pub fn parse_flag(text: &str) -> std::result::Result<PlatformSpec, String> {
    parse(text).map_err(|error| format!("{error:#}"))
}

fn known_list(registry: &Registry) -> String {
    let builds = registry
        .entries
        .iter()
        .filter(|entry| entry.build.is_some())
        .map(|entry| entry.name.as_str())
        .collect::<Vec<_>>();
    let releases = registry
        .entries
        .iter()
        .filter(|entry| entry.build.is_none())
        .map(|entry| entry.name.as_str())
        .collect::<Vec<_>>();
    format!(
        "releases {}; builds {}",
        releases.join(", "),
        builds.join(", ")
    )
}

#[cfg(test)]
mod tests;
