//! Reusable "Attributes & claims" editor for a SAML/OIDC enterprise app's
//! claims-mapping policy. Shared by the enterprise-app detail "SSO" tab and the
//! "New SSO application" wizard so the (large) editing surface isn't duplicated.
//!
//! This is **pure presentation + state**: the caller owns the save action (and
//! the `Policy.ReadWrite.ApplicationConfiguration` consent flow). It builds a
//! [`ClaimsEditorState`] from the loaded [`ClaimsPolicyDto`], renders the editor,
//! and on save reads `state.to_dto()` back. Policy-level fields the editor
//! doesn't model (group filter / issuer / audience overrides) ride along in
//! `preserved_options` and are surfaced as a read-only note.

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Input, Select};

use crate::bindings::sso::{
    ClaimSchemaEntryDto, ClaimsPolicyDto, ClaimsTransformationDto, TransformInputClaimDto,
    TransformOutputClaimDto, TransformParamDto,
};

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
/// See <https://learn.microsoft.com/entra/identity-platform/saml-claims-customization>.
const BASIC_CLAIM_SET: [(&str, &str, &str, bool); 5] = [
    (
        "Name ID (subject)",
        "nameid (format emailAddress)",
        "userprincipalname",
        false,
    ),
    (
        "name",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
        "userprincipalname",
        true,
    ),
    (
        "emailaddress",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        "mail",
        true,
    ),
    (
        "givenname",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
        "givenname",
        true,
    ),
    (
        "surname",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
        "surname",
        true,
    ),
];

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
            extension_id: RwSignal::new(String::new()),
            value: RwSignal::new(String::new()),
            saml_claim_type: RwSignal::new(saml_uri.to_string()),
            jwt_claim_type: RwSignal::new(String::new()),
            saml_name_form: RwSignal::new(String::new()),
        })
    });
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
    /// Source attribute, or the transformation id when `source == transformation`.
    attribute: RwSignal<String>,
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

    /// Clears all rows back to empty (the wizard reuses one instance across
    /// opens and resets it on close).
    pub fn reset(&self) {
        // Restore the same defaults as `empty()`. Critically `include_basic`
        // follows the DTO default (true), not `false`: the wizard reuses one
        // instance across opens, so resetting it to `false` on close made a
        // reopened wizard start with the basic claim set unchecked — silently
        // suppressing Entra's default claims on the next save.
        let defaults = ClaimsPolicyDto::default();
        self.include_basic.set(defaults.include_basic_claim_set);
        self.schema.set(Vec::new());
        self.transforms.set(Vec::new());
        self.preserved.set(None);
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
            (!pid.is_empty() || !value.is_empty()).then_some(TransformParamDto { id: pid, value })
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
                    {BASIC_CLAIM_SET
                        .iter()
                        .map(|&(name, uri, src, overridable)| {
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
                    "Transformations generate a claim's value (Join, ExtractMailPrefix, case, RegexReplace). Reference one from a claim whose source is \"Transformation\" by matching its id."
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
                            <Input value=row.attribute placeholder="Source attribute (e.g. userprincipalname)" />
                        }
                    })
            }}
            {move || {
                is_transformation()
                    .then(|| {
                        view! { <Input value=row.attribute placeholder="Transformation id" /> }
                    })
            }}
            {move || {
                is_constant()
                    .then(|| view! { <Input value=row.value placeholder="Constant value" /> })
            }}
            {move || {
                is_directory()
                    .then(|| {
                        view! {
                            <Input
                                value=row.extension_id
                                placeholder="Extension attribute (optional)"
                            />
                        }
                    })
            }}
            <Input value=row.saml_claim_type placeholder="SAML claim URI" />
            <Input value=row.jwt_claim_type placeholder="JWT (token) claim name" />
            <Input value=row.saml_name_form placeholder="SAML name format (optional)" />
            <Button
                appearance=Signal::derive(|| ButtonAppearance::Subtle)
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
                <Input value=row.id placeholder="Transformation id" />
                <Select value=row.method>
                    {TRANSFORM_METHODS
                        .iter()
                        .map(|m| view! { <option value=*m>{*m}</option> })
                        .collect_view()}
                </Select>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Subtle)
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
                            <Input value=ir.reference_id placeholder="ClaimTypeReferenceId" />
                            <Input
                                value=ir.claim_type
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
                                on_click=Box::new(move |_| {
                                    row.inputs.update(|v| v.retain(|x| x.key != ikey));
                                })
                            >
                                "✕"
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
                            <Input value=pr.id placeholder="Parameter id (e.g. separator)" />
                            <Input value=pr.value placeholder="Value" />
                            <Button
                                appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                on_click=Box::new(move |_| {
                                    row.params.update(|v| v.retain(|x| x.key != pkey));
                                })
                            >
                                "✕"
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
                            <Input value=or.reference_id placeholder="ClaimTypeReferenceId" />
                            <Input
                                value=or.claim_type
                                placeholder="TransformationClaimType (e.g. outputClaim)"
                            />
                            <Button
                                appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                on_click=Box::new(move |_| {
                                    row.outputs.update(|v| v.retain(|x| x.key != okey));
                                })
                            >
                                "✕"
                            </Button>
                        </div>
                    }
                    .into_any()
                },
            )}
        </div>
    }
}
