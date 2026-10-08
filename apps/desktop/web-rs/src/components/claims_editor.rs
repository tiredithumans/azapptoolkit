//! Reusable "Attributes & claims" editor for a SAML/OIDC enterprise app's
//! claims-mapping policy. Shared by the enterprise-app detail "SSO" tab and the
//! "New SSO application" wizard so the (large) editing surface isn't duplicated.
//!
//! This is **pure presentation + state**: the caller owns the save action (and
//! the claims-mapping policy consent flow). It builds a
//! [`ClaimsEditorState`] from the loaded [`ClaimsPolicyDto`], renders the editor,
//! and on save reads `state.to_dto()` back. Policy-level fields the editor
//! doesn't model (group filter / issuer / audience overrides) ride along in
//! `preserved_options` and are surfaced as a read-only note.

use std::sync::atomic::{AtomicUsize, Ordering};

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Input, Select};

use crate::bindings::sso::{
    ClaimSchemaEntryDto, ClaimsPolicyDto, ClaimsTransformationDto, DEFAULT_NAME_ID_ATTRIBUTE,
    DEFAULT_SAML_CLAIMS, TransformInputClaimDto, TransformOutputClaimDto, TransformParamDto,
};
use crate::components::ui::Callout;

/// The directory `Source` values plus the UI-only `constant` sentinel (a claim
/// with no source, just a static `Value`).
const SOURCE_OPTIONS: [(&str, &str); 7] = [
    ("user", "User"),
    ("application", "Application"),
    ("resource", "Resource"),
    ("audience", "Audience"),
    ("company", "Company"),
    ("transformation", "Transformation"),
    ("constant", "Constant value"),
];

/// Supported `TransformationMethod`s (claims-mapping policy).
const TRANSFORM_METHODS: [&str; 5] = [
    "Join",
    "ExtractMailPrefix",
    "ToLowercase()",
    "ToUppercase()",
    "RegexReplace()",
];

/// The default SAML claims Entra emits when `IncludeBasicClaimSet` is true.
/// Defined by Microsoft Entra (not fetchable via Graph), so we list it read-only
/// to keep "Include the basic claim set" from being an opaque toggle. Each tuple
/// is `(claim name, SAML claim URI, source `user` attribute, overridable)`. The
/// source attribute is the bare id (displayed as `user.{attr}`) so an "Edit"
/// click can seed an equivalent schema row that *overrides* the default — Entra
/// lets a schema entry with the same `SamlClaimType` supersede the basic one.
/// `Name ID` is reference-only (`overridable = false`): its "URI" here is a
/// descriptive placeholder, and the NameID/subject has its own sourcing rules.
/// The four overridable rows come from `dto::sso::DEFAULT_SAML_CLAIMS`, the one
/// list the "Attributes & claims" view also reads.
/// See <https://learn.microsoft.com/entra/identity-platform/saml-claims-customization>.
fn basic_claim_set() -> Vec<(&'static str, &'static str, &'static str, bool)> {
    std::iter::once((
        "Name ID (subject)",
        "nameid (format emailAddress)",
        DEFAULT_NAME_ID_ATTRIBUTE,
        false,
    ))
    .chain(
        DEFAULT_SAML_CLAIMS
            .iter()
            .map(|&(name, uri, attribute)| (name, uri, attribute, true)),
    )
    .collect()
}

/// Pushes a pre-filled schema row that overrides a basic claim (source `user`,
/// the given attribute, and the basic claim's SAML URI), ready to tweak + save.
fn seed_basic_override(
    schema: RwSignal<Vec<SchemaRow>>,
    seq: RwSignal<usize>,
    attribute: &str,
    saml_uri: &str,
) {
    schema.update(|rows| {
        rows.push(SchemaRow {
            key: next_key(seq),
            source: RwSignal::new("user".to_string()),
            attribute: RwSignal::new(attribute.to_string()),
            transformation_id: RwSignal::new(String::new()),
            extension_id: RwSignal::new(String::new()),
            value: RwSignal::new(String::new()),
            saml_claim_type: RwSignal::new(saml_uri.to_string()),
            jwt_claim_type: RwSignal::new(String::new()),
            saml_name_form: RwSignal::new(String::new()),
        })
    });
}

/// Distinguishes the generated `id`s of every [`LabelledInput`] in the DOM: the
/// wizard and an open SSO tab (one per open enterprise app) can each mount an
/// editor, so a per-row key alone would collide across editors.
static NEXT_FIELD_ID: AtomicUsize = AtomicUsize::new(0);

/// A thaw `Input` named by a visually-hidden `<label for>`. A placeholder alone
/// vanishes on the first keystroke and is not a reliable accessible name, and
/// `attr:aria-label` on thaw's `Input` lands on its wrapper `<span>`, not the
/// `<input>` — the `id` prop is the one thaw forwards to the real control.
#[component]
fn LabelledInput(
    value: RwSignal<String>,
    #[prop(into)] label: String,
    #[prop(into)] placeholder: String,
) -> impl IntoView {
    let id = format!(
        "claims-field-{}",
        NEXT_FIELD_ID.fetch_add(1, Ordering::Relaxed)
    );
    view! {
        <label class="visually-hidden" for=id.clone()>{label}</label>
        <Input id=id value=value placeholder=placeholder />
    }
}

/// Returns the next monotonically increasing key and advances the counter. Keys
/// let us remove a specific row without index juggling across re-renders.
fn next_key(seq: RwSignal<usize>) -> usize {
    let k = seq.get_untracked();
    seq.set(k + 1);
    k
}

/// Trimmed, non-empty value of a string signal (read untracked, for save).
fn opt(sig: RwSignal<String>) -> Option<String> {
    let v = sig.get_untracked().trim().to_string();
    (!v.is_empty()).then_some(v)
}

// ---------------- editable row structs (inner signals are `Copy`) ----------------

#[derive(Clone, Copy)]
struct SchemaRow {
    key: usize,
    /// One of [`SOURCE_OPTIONS`] (directory source or `constant`).
    source: RwSignal<String>,
    /// Source attribute; for `source == transformation`, the claim's own id
    /// (Graph `ID`, what the transformation's output claim references).
    attribute: RwSignal<String>,
    /// The generating transformation's id (Graph `TransformationID`) — only
    /// sent when `source == transformation`.
    transformation_id: RwSignal<String>,
    /// Directory extension attribute (alternative to `attribute`).
    extension_id: RwSignal<String>,
    /// Static value (when `source == constant`).
    value: RwSignal<String>,
    saml_claim_type: RwSignal<String>,
    jwt_claim_type: RwSignal<String>,
    saml_name_form: RwSignal<String>,
}

#[derive(Clone, Copy)]
struct TransformRow {
    key: usize,
    id: RwSignal<String>,
    method: RwSignal<String>,
    inputs: RwSignal<Vec<TInputRow>>,
    params: RwSignal<Vec<TParamRow>>,
    outputs: RwSignal<Vec<TOutputRow>>,
}

#[derive(Clone, Copy)]
struct TInputRow {
    key: usize,
    reference_id: RwSignal<String>,
    claim_type: RwSignal<String>,
    multi: RwSignal<bool>,
}

#[derive(Clone, Copy)]
struct TParamRow {
    key: usize,
    id: RwSignal<String>,
    value: RwSignal<String>,
    /// `DataType` as loaded — not editable, preserved so a save never drops it.
    data_type: RwSignal<Option<String>>,
}

#[derive(Clone, Copy)]
struct TOutputRow {
    key: usize,
    reference_id: RwSignal<String>,
    claim_type: RwSignal<String>,
}

/// Copy handle to all editor state. Created by the parent via [`Self::from_dto`],
/// passed to [`ClaimsEditor`], and read back on save with [`Self::to_dto`].
#[derive(Clone, Copy)]
pub struct ClaimsEditorState {
    include_basic: RwSignal<bool>,
    schema: RwSignal<Vec<SchemaRow>>,
    transforms: RwSignal<Vec<TransformRow>>,
    /// Opaque JSON of policy-level fields the editor doesn't model, round-tripped.
    preserved: RwSignal<Option<String>>,
    seq: RwSignal<usize>,
}

impl ClaimsEditorState {
    /// Seeds editor state from a loaded policy. Must run inside a reactive owner
    /// (i.e. during a component's render).
    pub fn from_dto(dto: &ClaimsPolicyDto) -> Self {
        let seq = RwSignal::new(0usize);
        let schema = dto
            .schema
            .iter()
            .map(|e| {
                // A constant claim has a value and no directory source.
                let source = match (&e.source, &e.value) {
                    (None, Some(_)) => "constant".to_string(),
                    (Some(s), _) => s.clone(),
                    _ => "user".to_string(),
                };
                SchemaRow {
                    key: next_key(seq),
                    source: RwSignal::new(source),
                    attribute: RwSignal::new(e.id.clone().unwrap_or_default()),
                    transformation_id: RwSignal::new(
                        e.transformation_id.clone().unwrap_or_default(),
                    ),
                    extension_id: RwSignal::new(e.extension_id.clone().unwrap_or_default()),
                    value: RwSignal::new(e.value.clone().unwrap_or_default()),
                    saml_claim_type: RwSignal::new(e.saml_claim_type.clone().unwrap_or_default()),
                    jwt_claim_type: RwSignal::new(e.jwt_claim_type.clone().unwrap_or_default()),
                    saml_name_form: RwSignal::new(e.saml_name_form.clone().unwrap_or_default()),
                }
            })
            .collect();
        let transforms = dto
            .transformations
            .iter()
            .map(|t| TransformRow {
                key: next_key(seq),
                id: RwSignal::new(t.id.clone()),
                method: RwSignal::new(t.method.clone()),
                inputs: RwSignal::new(
                    t.input_claims
                        .iter()
                        .map(|c| TInputRow {
                            key: next_key(seq),
                            reference_id: RwSignal::new(c.claim_type_reference_id.clone()),
                            claim_type: RwSignal::new(c.transformation_claim_type.clone()),
                            multi: RwSignal::new(c.treat_as_multi_value.unwrap_or(false)),
                        })
                        .collect(),
                ),
                params: RwSignal::new(
                    t.input_parameters
                        .iter()
                        .map(|p| TParamRow {
                            key: next_key(seq),
                            id: RwSignal::new(p.id.clone()),
                            value: RwSignal::new(p.value.clone()),
                            data_type: RwSignal::new(p.data_type.clone()),
                        })
                        .collect(),
                ),
                outputs: RwSignal::new(
                    t.output_claims
                        .iter()
                        .map(|c| TOutputRow {
                            key: next_key(seq),
                            reference_id: RwSignal::new(c.claim_type_reference_id.clone()),
                            claim_type: RwSignal::new(c.transformation_claim_type.clone()),
                        })
                        .collect(),
                ),
            })
            .collect();
        Self {
            include_basic: RwSignal::new(dto.include_basic_claim_set),
            schema: RwSignal::new(schema),
            transforms: RwSignal::new(transforms),
            preserved: RwSignal::new(dto.preserved_options.clone()),
            seq,
        }
    }

    /// Empty editor state (the "New SSO application" wizard's initial value).
    pub fn empty() -> Self {
        Self::from_dto(&ClaimsPolicyDto::default())
    }

    /// Advisory checks on the edited state (F385) — edits that Graph would
    /// reject, or that would silently strip claims, named BEFORE the operator
    /// saves. Deliberately advisory, never a gate: saving a rejected policy
    /// still leaves the app usable, and the save path now re-resolves live
    /// state first (the `ClaimsWrite` ladder), so blocking was never needed —
    /// the operator just must not type into these blind.
    ///
    /// Reads are tracked (`get`, not `get_untracked`) so the callout re-renders
    /// while the operator edits, not only when a row is added or removed.
    pub fn problems(&self) -> Vec<String> {
        // Build the same DTO `to_dto` would send, then read the footguns off
        // it — the advisory must describe what would actually reach Graph,
        // including which half-typed rows get dropped on the way.
        let dto = {
            let schema: Vec<ClaimSchemaEntryDto> = self
                .schema
                .get()
                .into_iter()
                .filter_map(schema_row_to_dto)
                .collect();
            let transformations: Vec<ClaimsTransformationDto> = self
                .transforms
                .get()
                .into_iter()
                .filter_map(transform_row_to_dto)
                .collect();
            ClaimsPolicyDto {
                include_basic_claim_set: self.include_basic.get(),
                schema,
                transformations,
                preserved_options: None,
            }
        };
        let mut problems: Vec<String> = Vec::new();

        if !dto.include_basic_claim_set && dto.schema.is_empty() {
            problems.push(
                "The basic claim set is off and no claims are defined: tokens will carry no \
                 identity claims at all — name, emailaddress, givenname and surname disappear \
                 from every assertion."
                    .to_string(),
            );
        }

        let transform_ids: Vec<&str> = dto
            .transformations
            .iter()
            .map(|t| t.id.as_str())
            .filter(|id| !id.trim().is_empty())
            .collect();

        for (i, e) in dto.schema.iter().enumerate() {
            let n = i + 1;
            if e.saml_claim_type.is_none() && e.jwt_claim_type.is_none() {
                problems.push(format!(
                    "Claim #{n} sets neither a SAML claim URI nor a JWT claim name — it cannot \
                     appear in a token."
                ));
            }
            if e.source.as_deref() == Some("transformation") {
                match e.transformation_id.as_deref() {
                    None => problems.push(format!(
                        "Claim #{n} is sourced from a transformation but names none — it emits \
                         no value."
                    )),
                    Some(tid) if !transform_ids.contains(&tid) => problems.push(format!(
                        "Claim #{n} names transformation '{tid}', which no transformation \
                         below defines."
                    )),
                    _ => {}
                }
            }
        }

        // A repeated "Edit" on the same basic claim (or a hand-made duplicate)
        // emits the same URI twice; only one value can land.
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut reported: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for e in &dto.schema {
            if let Some(uri) = e.saml_claim_type.as_deref()
                && !seen.insert(uri)
                && reported.insert(uri)
            {
                problems.push(format!(
                    "More than one claim emits '{uri}' — only one value can land; remove or \
                     rename a duplicate."
                ));
            }
        }

        for t in &dto.transformations {
            if t.output_claims.is_empty() {
                let label = if t.id.trim().is_empty() {
                    "A transformation".to_string()
                } else {
                    format!("Transformation '{}'", t.id.trim())
                };
                problems.push(format!(
                    "{label} has no output claim — it computes a value that no claim emits."
                ));
            }
        }

        problems
    }

    /// Reads the edited policy back. Fully-empty schema/transformation rows are
    /// dropped so a half-typed row doesn't reach Graph.
    pub fn to_dto(&self) -> ClaimsPolicyDto {
        let schema = self
            .schema
            .get_untracked()
            .into_iter()
            .filter_map(schema_row_to_dto)
            .collect();
        let transformations = self
            .transforms
            .get_untracked()
            .into_iter()
            .filter_map(transform_row_to_dto)
            .collect();
        ClaimsPolicyDto {
            include_basic_claim_set: self.include_basic.get_untracked(),
            schema,
            transformations,
            preserved_options: self.preserved.get_untracked(),
        }
    }
}

/// Converts one [`SchemaRow`] to a DTO entry, or `None` if it carries nothing.
fn schema_row_to_dto(row: SchemaRow) -> Option<ClaimSchemaEntryDto> {
    let source = row.source.get_untracked();
    let entry = if source == "constant" {
        ClaimSchemaEntryDto {
            source: None,
            id: None,
            transformation_id: None,
            extension_id: None,
            value: opt(row.value),
            saml_claim_type: opt(row.saml_claim_type),
            jwt_claim_type: opt(row.jwt_claim_type),
            saml_name_form: opt(row.saml_name_form),
        }
    } else {
        ClaimSchemaEntryDto {
            source: (!source.is_empty()).then_some(source.clone()),
            id: opt(row.attribute),
            // Only a transformation-sourced claim names a transformation.
            transformation_id: (source == "transformation")
                .then(|| opt(row.transformation_id))
                .flatten(),
            // Extension attributes only apply to directory sources.
            extension_id: (source != "transformation")
                .then(|| opt(row.extension_id))
                .flatten(),
            value: None,
            saml_claim_type: opt(row.saml_claim_type),
            jwt_claim_type: opt(row.jwt_claim_type),
            saml_name_form: opt(row.saml_name_form),
        }
    };
    let empty = entry.id.is_none()
        && entry.transformation_id.is_none()
        && entry.extension_id.is_none()
        && entry.value.is_none()
        && entry.saml_claim_type.is_none()
        && entry.jwt_claim_type.is_none();
    (!empty).then_some(entry)
}

/// Converts one [`TransformRow`] to a DTO, or `None` if id and method are empty.
fn transform_row_to_dto(row: TransformRow) -> Option<ClaimsTransformationDto> {
    let id = row.id.get_untracked().trim().to_string();
    let method = row.method.get_untracked().trim().to_string();
    if id.is_empty() && method.is_empty() {
        return None;
    }
    let input_claims = row
        .inputs
        .get_untracked()
        .into_iter()
        .filter_map(|i| {
            let reference_id = i.reference_id.get_untracked().trim().to_string();
            let claim_type = i.claim_type.get_untracked().trim().to_string();
            (!reference_id.is_empty() || !claim_type.is_empty()).then_some(TransformInputClaimDto {
                claim_type_reference_id: reference_id,
                transformation_claim_type: claim_type,
                treat_as_multi_value: i.multi.get_untracked().then_some(true),
            })
        })
        .collect();
    let input_parameters = row
        .params
        .get_untracked()
        .into_iter()
        .filter_map(|p| {
            let pid = p.id.get_untracked().trim().to_string();
            let value = p.value.get_untracked().trim().to_string();
            (!pid.is_empty() || !value.is_empty()).then_some(TransformParamDto {
                id: pid,
                value,
                data_type: p.data_type.get_untracked(),
            })
        })
        .collect();
    let output_claims = row
        .outputs
        .get_untracked()
        .into_iter()
        .filter_map(|o| {
            let reference_id = o.reference_id.get_untracked().trim().to_string();
            let claim_type = o.claim_type.get_untracked().trim().to_string();
            (!reference_id.is_empty() || !claim_type.is_empty()).then_some(
                TransformOutputClaimDto {
                    claim_type_reference_id: reference_id,
                    transformation_claim_type: claim_type,
                },
            )
        })
        .collect();
    Some(ClaimsTransformationDto {
        id,
        method,
        input_claims,
        input_parameters,
        output_claims,
    })
}

// ---------------- view ----------------

#[component]
pub fn ClaimsEditor(state: ClaimsEditorState) -> impl IntoView {
    let ClaimsEditorState {
        include_basic,
        schema,
        transforms,
        preserved,
        seq,
    } = state;

    let add_claim = move |_| {
        schema.update(|rows| {
            rows.push(SchemaRow {
                key: next_key(seq),
                source: RwSignal::new("user".to_string()),
                attribute: RwSignal::new(String::new()),
                transformation_id: RwSignal::new(String::new()),
                extension_id: RwSignal::new(String::new()),
                value: RwSignal::new(String::new()),
                saml_claim_type: RwSignal::new(String::new()),
                jwt_claim_type: RwSignal::new(String::new()),
                saml_name_form: RwSignal::new(String::new()),
            })
        });
    };
    let add_transform = move |_| {
        transforms.update(|rows| {
            rows.push(TransformRow {
                key: next_key(seq),
                id: RwSignal::new(String::new()),
                method: RwSignal::new("Join".to_string()),
                inputs: RwSignal::new(Vec::new()),
                params: RwSignal::new(Vec::new()),
                outputs: RwSignal::new(Vec::new()),
            })
        });
    };

    view! {
        <div class="claims-editor">
            <label class="claims-editor__basic">
                <input
                    type="checkbox"
                    prop:checked=move || include_basic.get()
                    on:change=move |ev| include_basic.set(event_target_checked(&ev))
                />
                "Include the basic claim set"
            </label>

            // ---- reference: what the basic claim set emits, with per-claim override ----
            <div class="claims-editor__basic-ref">
                <span class="claims-editor__basic-ref-caption">
                    "Default SAML claims Entra emits when this is on:"
                </span>
                <div class="claims-editor__basic-ref-grid">
                    <span class="claims-editor__basic-ref-head">"Claim"</span>
                    <span class="claims-editor__basic-ref-head">"SAML claim URI"</span>
                    <span class="claims-editor__basic-ref-head">"Source"</span>
                    <span class="claims-editor__basic-ref-head"></span>
                    {basic_claim_set()
                        .into_iter()
                        .map(|(name, uri, src, overridable)| {
                            let action = if overridable {
                                view! {
                                    <Button
                                        appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                        on_click=Box::new(move |_| {
                                            seed_basic_override(schema, seq, src, uri)
                                        })
                                    >
                                        "Edit"
                                    </Button>
                                }
                                    .into_any()
                            } else {
                                view! { <span></span> }.into_any()
                            };
                            view! {
                                <span class="claims-editor__basic-ref-name">{name}</span>
                                <span class="claims-editor__basic-ref-uri">{uri}</span>
                                <span class="claims-editor__basic-ref-src">
                                    {format!("user.{src}")}
                                </span>
                                <span class="claims-editor__basic-ref-actions">{action}</span>
                            }
                        })
                        .collect_view()}
                </div>
                <span class="claims-editor__basic-ref-note">
                    "Defined by Microsoft Entra. Select Edit to override a default (seeds a pre-filled claim row below to tweak and save); other claims you add are emitted alongside these."
                </span>
            </div>

            // ---- claim schema rows ----
            <div class="row-between">
                <Body1 class="hint">
                    "Each claim maps a source (attribute / constant / transformation) to a SAML claim URI and/or a JWT (token) claim name."
                </Body1>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                    on_click=Box::new(add_claim)
                >
                    "Add claim"
                </Button>
            </div>
            // Keyed so adding/removing one claim patches only that row instead of
            // tearing down and rebuilding every row's <Select>/<Input> DOM. The
            // stable `key` field exists for exactly this.
            <For each=move || schema.get() key=|row| row.key let:row>
                <SchemaRowView row=row schema=schema />
            </For>

            // ---- transformations ----
            <div class="row-between claims-editor__transforms-head">
                <Body1 class="hint">
                    "Transformations generate a claim's value (Join, ExtractMailPrefix, case, RegexReplace). A claim whose source is \"Transformation\" names the transformation in its Transformation id; the transformation's output claim references that claim's id."
                </Body1>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                    on_click=Box::new(add_transform)
                >
                    "Add transformation"
                </Button>
            </div>
            <For each=move || transforms.get() key=|row| row.key let:row>
                <TransformRowView row=row transforms=transforms seq=seq />
            </For>

            // ---- preserved advanced options note ----
            {move || {
                preserved
                    .get()
                    .is_some()
                    .then(|| {
                        view! {
                            <Body1 class="hint claims-editor__preserved">
                                "This policy also has advanced options (e.g. group filter, issuer / audience overrides) that aren't editable here. They're preserved unchanged when you save."
                            </Body1>
                        }
                    })
            }}

            // ---- advisory validation (F385) ----
            // Sits directly above the caller's Save (in the SSO tab and the
            // wizard alike). Advisory by design — see `ClaimsEditorState::problems`.
            {move || {
                let problems = state.problems();
                (!problems.is_empty()).then(|| {
                    view! {
                        <Callout tone="warn">
                            <ul>
                                {problems
                                    .into_iter()
                                    .map(|p| view! { <li>{p}</li> })
                                    .collect_view()}
                            </ul>
                        </Callout>
                    }
                })
            }}
        </div>
    }
}

#[component]
fn SchemaRowView(row: SchemaRow, schema: RwSignal<Vec<SchemaRow>>) -> impl IntoView {
    let key = row.key;
    let is_constant = move || row.source.get() == "constant";
    let is_transformation = move || row.source.get() == "transformation";
    let is_directory = move || !is_constant() && !is_transformation();

    view! {
        <div class="claims-editor__row">
            <Select value=row.source>
                {SOURCE_OPTIONS
                    .iter()
                    .map(|(v, label)| view! { <option value=*v>{*label}</option> })
                    .collect_view()}
            </Select>
            // attribute / transformation id / constant value (one applies)
            {move || {
                is_directory()
                    .then(|| {
                        view! {
                            <LabelledInput
                                value=row.attribute
                                label="Source attribute"
                                placeholder="Source attribute (e.g. userprincipalname)"
                            />
                        }
                    })
            }}
            {move || {
                is_transformation()
                    .then(|| {
                        view! {
                            <LabelledInput
                                value=row.attribute
                                label="Claim id"
                                placeholder="Claim id (output claims reference this)"
                            />
                            <LabelledInput
                                value=row.transformation_id
                                label="Transformation id"
                                placeholder="Transformation id"
                            />
                        }
                    })
            }}
            {move || {
                is_constant()
                    .then(|| view! {
                        <LabelledInput
                            value=row.value
                            label="Constant value"
                            placeholder="Constant value"
                        />
                    })
            }}
            {move || {
                is_directory()
                    .then(|| {
                        view! {
                            <LabelledInput
                                value=row.extension_id
                                label="Extension attribute"
                                placeholder="Extension attribute (optional)"
                            />
                        }
                    })
            }}
            <LabelledInput value=row.saml_claim_type label="SAML claim URI" placeholder="SAML claim URI" />
            <LabelledInput
                value=row.jwt_claim_type
                label="JWT claim name"
                placeholder="JWT (token) claim name"
            />
            <LabelledInput
                value=row.saml_name_form
                label="SAML name format"
                placeholder="SAML name format (optional)"
            />
            <Button
                class="button--danger"
                appearance=Signal::derive(|| ButtonAppearance::Subtle)
                // Names the claim the row emits (SAML URI, else JWT name), so
                // a list of rows is not N identical "Remove"s.
                attr:aria-label=move || {
                    let saml = row.saml_claim_type.get();
                    let claim = if saml.trim().is_empty() { row.jwt_claim_type.get() } else { saml };
                    if claim.trim().is_empty() {
                        "Remove claim".to_string()
                    } else {
                        format!("Remove claim {}", claim.trim())
                    }
                }
                on_click=Box::new(move |_| {
                    schema.update(|rows| rows.retain(|r| r.key != key));
                })
            >
                "Remove"
            </Button>
        </div>
    }
}

/// One labeled sub-list inside a transform row (input claims / parameters /
/// output claims): the "Add" header plus the reactive row list. The per-row
/// controls differ across the three, so the caller supplies `row_view`; this
/// dedups the surrounding section scaffold.
fn sub_section<R>(
    label: &'static str,
    add_label: &'static str,
    rows: RwSignal<Vec<R>>,
    on_add: impl Fn(leptos::ev::MouseEvent) + Send + Sync + 'static,
    key_of: impl Fn(&R) -> usize + Clone + Send + Sync + 'static,
    row_view: impl Fn(R) -> AnyView + Clone + Send + Sync + 'static,
) -> impl IntoView
where
    R: Clone + Send + Sync + 'static,
{
    view! {
        <div class="claims-editor__sub">
            <div class="row-between">
                <span class="claims-editor__sub-label">{label}</span>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Subtle)
                    on_click=Box::new(on_add)
                >
                    {add_label}
                </Button>
            </div>
            // Keyed so adding/removing one sub-row doesn't rebuild the sibling
            // inputs/parameters/outputs in the same transform.
            <For each=move || rows.get() key=key_of children=row_view />
        </div>
    }
}

#[component]
fn TransformRowView(
    row: TransformRow,
    transforms: RwSignal<Vec<TransformRow>>,
    seq: RwSignal<usize>,
) -> impl IntoView {
    let key = row.key;
    let add_input = move |_| {
        row.inputs.update(|v| {
            v.push(TInputRow {
                key: next_key(seq),
                reference_id: RwSignal::new(String::new()),
                claim_type: RwSignal::new(String::new()),
                multi: RwSignal::new(false),
            })
        });
    };
    let add_param = move |_| {
        row.params.update(|v| {
            v.push(TParamRow {
                key: next_key(seq),
                id: RwSignal::new(String::new()),
                value: RwSignal::new(String::new()),
                data_type: RwSignal::new(None),
            })
        });
    };
    let add_output = move |_| {
        row.outputs.update(|v| {
            v.push(TOutputRow {
                key: next_key(seq),
                reference_id: RwSignal::new(String::new()),
                claim_type: RwSignal::new(String::new()),
            })
        });
    };

    view! {
        <div class="claims-editor__transform">
            <div class="claims-editor__transform-head">
                <LabelledInput value=row.id label="Transformation id" placeholder="Transformation id" />
                <Select value=row.method>
                    {TRANSFORM_METHODS
                        .iter()
                        .map(|m| view! { <option value=*m>{*m}</option> })
                        .collect_view()}
                </Select>
                <Button
                    class="button--danger"
                    appearance=Signal::derive(|| ButtonAppearance::Subtle)
                    attr:aria-label=move || {
                        let id = row.id.get();
                        if id.trim().is_empty() {
                            "Remove transformation".to_string()
                        } else {
                            format!("Remove transformation {}", id.trim())
                        }
                    }
                    on_click=Box::new(move |_| {
                        transforms.update(|rows| rows.retain(|r| r.key != key));
                    })
                >
                    "Remove"
                </Button>
            </div>

            {sub_section(
                "Input claims",
                "Add input",
                row.inputs,
                add_input,
                |ir: &TInputRow| ir.key,
                move |ir: TInputRow| {
                    let ikey = ir.key;
                    view! {
                        <div class="claims-editor__sub-row">
                            <LabelledInput
                                value=ir.reference_id
                                label="Input claim ClaimTypeReferenceId"
                                placeholder="ClaimTypeReferenceId"
                            />
                            <LabelledInput
                                value=ir.claim_type
                                label="Input claim TransformationClaimType"
                                placeholder="TransformationClaimType (e.g. string1)"
                            />
                            <label class="claims-editor__multi">
                                <input
                                    type="checkbox"
                                    prop:checked=move || ir.multi.get()
                                    on:change=move |ev| ir.multi.set(event_target_checked(&ev))
                                />
                                "Multi"
                            </label>
                            <Button
                                appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                attr:aria-label=move || {
                                    let id = ir.reference_id.get();
                                    if id.trim().is_empty() {
                                        "Remove input claim".to_string()
                                    } else {
                                        format!("Remove input claim {}", id.trim())
                                    }
                                }
                                attr:title="Remove"
                                on_click=Box::new(move |_| {
                                    row.inputs.update(|v| v.retain(|x| x.key != ikey));
                                })
                            >
                                <span aria-hidden="true">"✕"</span>
                            </Button>
                        </div>
                    }
                    .into_any()
                },
            )}

            {sub_section(
                "Input parameters",
                "Add parameter",
                row.params,
                add_param,
                |pr: &TParamRow| pr.key,
                move |pr: TParamRow| {
                    let pkey = pr.key;
                    view! {
                        <div class="claims-editor__sub-row">
                            <LabelledInput
                                value=pr.id
                                label="Parameter id"
                                placeholder="Parameter id (e.g. separator)"
                            />
                            <LabelledInput value=pr.value label="Parameter value" placeholder="Value" />
                            <Button
                                appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                attr:aria-label=move || {
                                    let id = pr.id.get();
                                    if id.trim().is_empty() {
                                        "Remove input parameter".to_string()
                                    } else {
                                        format!("Remove input parameter {}", id.trim())
                                    }
                                }
                                attr:title="Remove"
                                on_click=Box::new(move |_| {
                                    row.params.update(|v| v.retain(|x| x.key != pkey));
                                })
                            >
                                <span aria-hidden="true">"✕"</span>
                            </Button>
                        </div>
                    }
                    .into_any()
                },
            )}

            {sub_section(
                "Output claims",
                "Add output",
                row.outputs,
                add_output,
                |or: &TOutputRow| or.key,
                move |or: TOutputRow| {
                    let okey = or.key;
                    view! {
                        <div class="claims-editor__sub-row">
                            <LabelledInput
                                value=or.reference_id
                                label="Output claim ClaimTypeReferenceId"
                                placeholder="ClaimTypeReferenceId"
                            />
                            <LabelledInput
                                value=or.claim_type
                                label="Output claim TransformationClaimType"
                                placeholder="TransformationClaimType (e.g. outputClaim)"
                            />
                            <Button
                                appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                attr:aria-label=move || {
                                    let id = or.reference_id.get();
                                    if id.trim().is_empty() {
                                        "Remove output claim".to_string()
                                    } else {
                                        format!("Remove output claim {}", id.trim())
                                    }
                                }
                                attr:title="Remove"
                                on_click=Box::new(move |_| {
                                    row.outputs.update(|v| v.retain(|x| x.key != okey));
                                })
                            >
                                <span aria-hidden="true">"✕"</span>
                            </Button>
                        </div>
                    }
                    .into_any()
                },
            )}
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Building rows allocates signals, which need an owner.
    fn with_owner<T>(f: impl FnOnce() -> T) -> T {
        let owner = Owner::new();
        let out = owner.with(f);
        owner.cleanup();
        out
    }

    fn schema_row(source: &str, attribute: &str, value: &str, saml: &str) -> SchemaRow {
        SchemaRow {
            key: 0,
            source: RwSignal::new(source.to_string()),
            attribute: RwSignal::new(attribute.to_string()),
            transformation_id: RwSignal::new(String::new()),
            extension_id: RwSignal::new(String::new()),
            value: RwSignal::new(value.to_string()),
            saml_claim_type: RwSignal::new(saml.to_string()),
            jwt_claim_type: RwSignal::new(String::new()),
            saml_name_form: RwSignal::new(String::new()),
        }
    }

    #[test]
    fn a_blank_schema_row_produces_no_dto_entry() {
        // The editor always keeps a trailing empty row for typing into. Emitting
        // it would PATCH a claims-mapping policy with a claim that names nothing.
        with_owner(|| {
            assert!(schema_row_to_dto(schema_row("user", "", "", "")).is_none());
            assert!(schema_row_to_dto(schema_row("", "", "", "")).is_none());
        });
    }

    #[test]
    fn a_constant_claim_carries_its_value_and_drops_the_source() {
        // `constant` is not a directory source: Graph rejects an entry that
        // carries both, so the converter must send `value` alone.
        with_owner(|| {
            let dto = schema_row_to_dto(schema_row("constant", "ignored", "acme", "urn:x"))
                .expect("a constant with a value is a real entry");
            assert_eq!(dto.value.as_deref(), Some("acme"));
            assert!(dto.source.is_none(), "constant has no directory source");
            assert!(dto.id.is_none(), "the attribute column is not a source id");
            assert_eq!(dto.saml_claim_type.as_deref(), Some("urn:x"));
        });
    }

    #[test]
    fn an_extension_id_is_dropped_for_a_transformation_source() {
        // Extension attributes only apply to directory sources; carrying one on
        // a transformation row sends a claim Graph cannot resolve.
        with_owner(|| {
            let mut row = schema_row("transformation", "t1", "", "urn:x");
            row.extension_id = RwSignal::new("extension_abc_dept".to_string());
            let dto = schema_row_to_dto(row).expect("transformation row is real");
            assert!(dto.extension_id.is_none());
            assert_eq!(dto.id.as_deref(), Some("t1"));

            let mut user_row = schema_row("user", "", "", "urn:x");
            user_row.extension_id = RwSignal::new("extension_abc_dept".to_string());
            let dto = schema_row_to_dto(user_row).expect("user row is real");
            assert_eq!(dto.extension_id.as_deref(), Some("extension_abc_dept"));
        });
    }

    #[test]
    fn a_transformation_row_sends_its_own_id_and_the_transformation_id_separately() {
        // Graph joins the transformation's output claim to the entry's own `ID`
        // and finds the transformation by `TransformationID` — two ids, never one.
        with_owner(|| {
            let row = schema_row("transformation", "DataJoin", "", "");
            row.transformation_id.set(" JoinTheData ".to_string());
            row.jwt_claim_type.set("JoinedData".to_string());
            let dto = schema_row_to_dto(row).expect("transformation row is real");
            assert_eq!(dto.id.as_deref(), Some("DataJoin"));
            assert_eq!(dto.transformation_id.as_deref(), Some("JoinTheData"));
        });
    }

    #[test]
    fn a_transformation_id_is_dropped_for_a_directory_source() {
        // A directory claim has no generating transformation; a stale id left
        // behind by switching the source would point Graph at one.
        with_owner(|| {
            let row = schema_row("user", "mail", "", "urn:x");
            row.transformation_id.set("JoinTheData".to_string());
            let dto = schema_row_to_dto(row).expect("user row is real");
            assert!(dto.transformation_id.is_none());
            assert_eq!(dto.id.as_deref(), Some("mail"));
        });
    }

    #[test]
    fn schema_values_are_trimmed() {
        with_owner(|| {
            let dto = schema_row_to_dto(schema_row("user", "  mail  ", "", " urn:x "))
                .expect("real entry");
            assert_eq!(dto.id.as_deref(), Some("mail"));
            assert_eq!(dto.saml_claim_type.as_deref(), Some("urn:x"));
        });
    }

    fn transform_row(id: &str, method: &str) -> TransformRow {
        TransformRow {
            key: 0,
            id: RwSignal::new(id.to_string()),
            method: RwSignal::new(method.to_string()),
            inputs: RwSignal::new(Vec::new()),
            params: RwSignal::new(Vec::new()),
            outputs: RwSignal::new(Vec::new()),
        }
    }

    fn editor_state(
        basic: bool,
        schema: Vec<SchemaRow>,
        transforms: Vec<TransformRow>,
    ) -> ClaimsEditorState {
        ClaimsEditorState {
            include_basic: RwSignal::new(basic),
            schema: RwSignal::new(schema),
            transforms: RwSignal::new(transforms),
            preserved: RwSignal::new(None),
            seq: RwSignal::new(0),
        }
    }

    /// A transformation with one output claim — the "well-formed" side of the
    /// advisory's transformation rules.
    fn transform_with_output(id: &str) -> TransformRow {
        let t = transform_row(id, "Join");
        t.outputs.set(vec![TOutputRow {
            key: 99,
            reference_id: RwSignal::new("claim1".to_string()),
            claim_type: RwSignal::new("JoinedData".to_string()),
        }]);
        t
    }

    #[test]
    fn a_well_formed_edit_reports_no_problems() {
        with_owner(|| {
            let plain = schema_row("user", "mail", "", "urn:email");
            let joined = schema_row("transformation", "claim1", "", "urn:joined");
            joined.transformation_id.set("DataJoin".to_string());
            let state = editor_state(
                true,
                vec![plain, joined],
                vec![transform_with_output("DataJoin")],
            );
            assert_eq!(state.problems(), Vec::<String>::new());

            // The empty editor a fresh wizard starts with: basic set on, no
            // rows. Nothing to warn about.
            assert!(
                editor_state(true, Vec::new(), Vec::new())
                    .problems()
                    .is_empty()
            );
        });
    }

    #[test]
    fn switching_the_basic_set_off_with_an_empty_schema_warns() {
        with_owner(|| {
            // This is the one edit that removes name/email/givenname/surname
            // from every assertion — the case the advisory exists for.
            let state = editor_state(false, Vec::new(), Vec::new());
            let problems = state.problems();
            assert_eq!(problems.len(), 1);
            assert!(
                problems[0].contains("no identity claims at all"),
                "{problems:?}"
            );

            // Unchecking with at least one defined claim is a legitimate edit.
            let state = editor_state(
                false,
                vec![schema_row("user", "mail", "", "urn:email")],
                Vec::new(),
            );
            assert!(state.problems().is_empty());
        });
    }

    #[test]
    fn a_claim_without_any_name_warns_but_a_jwt_only_claim_does_not() {
        with_owner(|| {
            // No SAML URI and no JWT name: the entry ships and emits nothing.
            let state = editor_state(true, vec![schema_row("user", "mail", "", "")], Vec::new());
            let problems = state.problems();
            assert_eq!(problems.len(), 1);
            assert!(problems[0].contains("neither a SAML claim URI nor a JWT claim name"));

            let jwt_only = schema_row("user", "mail", "", "");
            jwt_only.jwt_claim_type.set("email".to_string());
            assert!(
                editor_state(true, vec![jwt_only], Vec::new())
                    .problems()
                    .is_empty()
            );
        });
    }

    #[test]
    fn transformation_sourced_claims_must_name_a_defined_transformation() {
        with_owner(|| {
            // Names nothing.
            let state = editor_state(
                true,
                vec![schema_row("transformation", "claim1", "", "urn:x")],
                Vec::new(),
            );
            assert!(
                state.problems()[0].contains("names none"),
                "{:?}",
                state.problems()
            );

            // Names a transformation no row defines.
            let row = schema_row("transformation", "claim1", "", "urn:x");
            row.transformation_id.set("NopeJoin".to_string());
            let state = editor_state(true, vec![row], Vec::new());
            assert!(state.problems()[0].contains("NopeJoin"));

            // Names one that exists (with outputs) → no advisory.
            let row = schema_row("transformation", "claim1", "", "urn:x");
            row.transformation_id.set("DataJoin".to_string());
            let state = editor_state(true, vec![row], vec![transform_with_output("DataJoin")]);
            assert!(state.problems().is_empty());
        });
    }

    #[test]
    fn duplicate_saml_uris_warn_once() {
        with_owner(|| {
            // Repeated "Edit" clicks seed exactly this: two rows emitting the
            // same URI, where only one value can land.
            let rows = vec![
                schema_row("user", "mail", "", "urn:email"),
                schema_row("user", "userprincipalname", "", "urn:email"),
                schema_row("user", "givenname", "", "urn:email"),
            ];
            let state = editor_state(true, rows, Vec::new());
            let problems = state.problems();
            assert_eq!(
                problems.len(),
                1,
                "one advisory per duplicated URI: {problems:?}"
            );
            assert!(problems[0].contains("urn:email"));
        });
    }

    #[test]
    fn a_transformation_without_output_claims_warns() {
        with_owner(|| {
            let state = editor_state(true, Vec::new(), vec![transform_row("DataJoin", "Join")]);
            let problems = state.problems();
            assert_eq!(problems.len(), 1);
            assert!(problems[0].contains("DataJoin"));
            assert!(problems[0].contains("no output claim"));
        });
    }

    #[test]
    fn a_transform_row_with_neither_id_nor_method_is_dropped() {
        with_owner(|| {
            assert!(transform_row_to_dto(transform_row("", "   ")).is_none());
            // One of the two is enough to mean the operator started a row.
            assert!(transform_row_to_dto(transform_row("t1", "")).is_some());
            assert!(transform_row_to_dto(transform_row("", "Join")).is_some());
        });
    }

    #[test]
    fn blank_transform_inputs_params_and_outputs_are_dropped() {
        // Each sub-list keeps its own trailing blank row in the editor.
        with_owner(|| {
            let row = transform_row("t1", "Join");
            row.inputs.set(vec![
                TInputRow {
                    key: 0,
                    reference_id: RwSignal::new("  ".to_string()),
                    claim_type: RwSignal::new(String::new()),
                    multi: RwSignal::new(false),
                },
                TInputRow {
                    key: 1,
                    reference_id: RwSignal::new(" ref1 ".to_string()),
                    claim_type: RwSignal::new(String::new()),
                    multi: RwSignal::new(true),
                },
            ]);
            row.params.set(vec![TParamRow {
                key: 0,
                id: RwSignal::new(String::new()),
                value: RwSignal::new(String::new()),
                data_type: RwSignal::new(None),
            }]);
            let dto = transform_row_to_dto(row).expect("real transform");
            assert_eq!(dto.input_claims.len(), 1);
            assert_eq!(dto.input_claims[0].claim_type_reference_id, "ref1");
            assert_eq!(
                dto.input_claims[0].treat_as_multi_value,
                Some(true),
                "false is sent as None so the payload stays minimal"
            );
            assert!(dto.input_parameters.is_empty());
            assert!(dto.output_claims.is_empty());
        });
    }

    #[test]
    fn seeding_a_basic_override_fills_a_user_sourced_row_from_the_table() {
        // The "override this basic claim" buttons are the only writers of these
        // rows, and a wrong SAML URI silently produces a claim the relying party
        // never sees. Only the `overridable` rows get a button, so those are the
        // rows pinned here — Name ID's "URI" is a descriptive placeholder that
        // must never be seeded.
        with_owner(|| {
            let overridable: Vec<_> = basic_claim_set().into_iter().filter(|r| r.3).collect();
            assert_eq!(
                overridable.len(),
                4,
                "every basic claim but Name ID is overridable"
            );
            for &(name, saml_uri, attribute, _) in &overridable {
                assert!(
                    saml_uri.starts_with("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/"),
                    "{name}: an overridable basic claim needs its real SAML URI, got {saml_uri}"
                );
                let schema = RwSignal::new(Vec::<SchemaRow>::new());
                let seq = RwSignal::new(0usize);
                seed_basic_override(schema, seq, attribute, saml_uri);

                let dto = schema
                    .with_untracked(|rows| {
                        assert_eq!(rows.len(), 1);
                        schema_row_to_dto(rows[0])
                    })
                    .expect("a seeded override is a real entry");
                assert_eq!(dto.source.as_deref(), Some("user"), "{name}");
                assert_eq!(dto.id.as_deref(), Some(attribute), "{name}");
                assert_eq!(dto.saml_claim_type.as_deref(), Some(saml_uri), "{name}");
                assert!(dto.value.is_none(), "{name}: an override is not a constant");

                // Keys stay unique so removing one row cannot take out another.
                seed_basic_override(schema, seq, attribute, saml_uri);
                schema.with_untracked(|rows| assert_ne!(rows[0].key, rows[1].key));
            }

            // The one non-overridable row is the placeholder-URI Name ID.
            let fixed: Vec<_> = basic_claim_set().into_iter().filter(|r| !r.3).collect();
            assert_eq!(fixed.len(), 1);
            assert!(
                !fixed[0].1.starts_with("http"),
                "Name ID's URI is a placeholder"
            );
        });
    }
}
