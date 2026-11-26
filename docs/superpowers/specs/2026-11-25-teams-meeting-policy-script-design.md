# Design — Project C3: Teams meeting access policy script (short)

**Intent.** Online-meeting, transcript, recording, artifact and virtual-event application permissions
reach only the meetings of users an app's *Teams application access policy* covers. Microsoft has no
API for these policies (Teams PowerShell only), so the toolkit generates the exact, safe PowerShell for
the operator to run, scoped to chosen users or one group, and explains how to check it. The user chose
this as "C3 meeting-policy script, then D".

**Microsoft facts (Microsoft Learn, 2026-11-25).**
- The policy gates `OnlineMeetings.Read.All`, `OnlineMeetings.ReadWrite.All`,
  `OnlineMeetingArtifact.Read.All`, `OnlineMeetingTranscript.Read.All`,
  `OnlineMeetingRecording.Read.All`, `VirtualEvent.Read.All`. With no policy granted, calls fail with
  "No application access policy found for this app".
- `New-CsApplicationAccessPolicy -Identity <name> -AppIds <appId> -Description <text>`;
  `Grant-CsApplicationAccessPolicy -PolicyName <name> -Identity <user object id>`, or `-Group <group
  object id> [-Rank n]`, or `-Global` (every user without their own policy).
- **A user holds one application access policy.** Granting a new one replaces theirs.
- Changes take up to 30 minutes to reach Graph.

**Goals.** A "Meeting policy…" action on the Permissions-tab rows and held-permission rows for these
permissions, opening a dialog that builds the script: policy name (default `azapptoolkit-<app>`), the
targets (users picked one by one, or one group, via the existing directory search), and either
**create a new policy** or **add the app to an existing policy** (`Set-CsApplicationAccessPolicy
-Identity <name> -AppIds @{Add='<appId>'}`, for users who already hold one). The output is a copy
block with `Connect-MicrosoftTeams`, the cmdlets, and check commands (`Get-CsApplicationAccessPolicy`
filtered to the app; the Global policy's AppIds). The Rule 24 checklist line for these grants points
to it.

**Non-goals.** Running PowerShell; reading existing policies (no API); `-Global` (never generated — the
dialog explains why); C2.

**Anti-goals.** A script an app's own display name can inject into (vendor names are
attacker-controlled): every value goes into a single-quoted PowerShell literal with `'` doubled, and
ids are GUID-checked. Silently replacing users' existing policies: the new-policy mode warns that a
user holds one policy and offers the add-to-existing mode instead.

**Approaches.** (1) Generated script — chosen. (2) The Teams admin service's undocumented REST API —
rejected: undocumented and fragile. (3) Guidance text only — the checklist already does that.

**How (my calls).** A pure, WASM-safe generator in core
(`teams_meeting_policy::script(&PolicyRequest) -> Result<String, PolicyScriptError>`) with table tests
(quoting, GUID checks, both modes, users vs group); a frontend dialog reusing `ModalShell`,
`DirectorySearch` and `CopyBlock`; no backend command and no Graph call. The entry point appears for
the permissions in the existing `TeamsMeetingAccessPolicy` mechanism table (plus
`VirtualEvent.Read.All`, which the policy also gates).

**Left to the builder.** Layout, copy, the default policy-name sanitising.
