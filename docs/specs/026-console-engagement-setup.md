# Spec 026 — Console: engagement setup and the signed-in bar

Sprint 6, story S6-3. Depends on: 002 (engagements, scope lock), 007 (console), 008 (sign-in).
Packages: `web/`, `docs/`.

## Goal

On staging, the first real user could create an engagement but could not do anything with it. The
console had no way to add a target, write a scope or activate the engagement. Those were API-only,
so the run launcher's target menu stayed empty. The header also gave no clear sign of who was
signed in.

When this spec is done, an engagement owner sets up a draft engagement in the console:
1. add targets;
2. save a scope generated from those targets, with an optional rate limit;
3. activate it with the authorisation reference.

The header always shows who is signed in and with which role. The API is unchanged. Every step
goes through the existing routes, so the scope lock, the validation and the audit trail are
exactly those of spec 002.

## User story

As the owner of a new engagement, I add the endpoint I am authorised to test, save its scope and
activate the engagement with the contract reference, without an API token, and then run a suite.

## Interface

- **API client** (`web/src/api.ts`):
  - `addTarget(id, type, spec)` → `POST /engagements/{id}/targets`;
  - `setScope(id, {allow, deny, roe})` → `PUT /engagements/{id}/scope`;
  - `activate(id, authorisation_ref)` → `POST /engagements/{id}/activate`.
- **Setup panel** on the engagement page, shown while the engagement is a draft:
  1. **Targets**: the list, and a form with:
     - type `llm_endpoint`, `agent` or `mcp_server`;
     - an absolute `http(s)` URL;
     - an optional model, for endpoints and agents.

     The spec sent is `{"url": …}` plus `"model"` when given.
  2. **Scope**: the allow rules generated from the targets:
     - endpoints and agents: their host, and their path and model when present;
     - MCP servers: their exact URL.

     Optionally a maximum number of requests per minute, saved as
     `roe.max_requests_per_minute`. The JSON that will be saved is shown before saving.
  3. **Activate**: the authorisation reference (contract or statement-of-work id, with its date)
     and an **Activate** button.
- **Locked view**: once the engagement is active, the panel shows the targets and the locked scope
  read-only.
- **Signed-in bar**: the header shows "Signed in as <name> · <email>" and the organisation role.
- **Sign-in buttons**: the primary button's label is legible. The console's global link colour no
  longer overrides button text, because it moves into Tailwind's base layer.

## Behaviour

1. **Owner only.** The setup controls are shown only to the engagement owner. Anyone else sees "Only
   the engagement owner can set up targets, scope and activation." The API enforces this
   regardless (spec 002).
2. **Validation stays server-side.** The console checks only that the URL is absolute `http(s)` and
   that a rate is a whole number of at least 1. Every API error (422 or 409) is shown as returned:
   an invalid target, an invalid scope, or activation without a scope, a target or a reference.
3. **Order.**
   - The scope can be saved once there is at least one target.
   - Activate is enabled only once a scope is saved, the saved scope still matches the targets,
     and the reference is non-empty.
   - Adding a target after saving marks the saved scope out of date: "Save the scope again to
     include the new target."
4. **After activation** the engagement page refetches. The run launcher now lists the targets and
   the scope pre-flight applies (spec 007).

## Acceptance criteria

- [x] An owner adds a target, saves the generated scope and activates a draft engagement through the
      API client calls above; errors from the API are shown.
- [x] The scope sent for an `llm_endpoint` with a URL and model has the host, the path and the model;
      for an `mcp_server` the exact URL; a rate becomes `roe.max_requests_per_minute`.
- [x] Activate stays disabled without a saved scope or a reference; a non-owner sees no controls.
- [x] An active engagement shows its targets and scope read-only.
- [x] The header shows name, email and role; the primary sign-in button's label is legible.

## Test cases

Web (`web/src/__tests__/engagement-setup.test.tsx`): add a target, save the scope (asserting the
body), activate; the scope request for an MCP server and with a rate; Activate disabled until the
scope and reference exist; an API error shown; a non-owner sees no controls; the read-only view
when active. `app-auth.test.tsx`: the signed-in bar.

## Out of scope

- Editing a locked scope (an audited owner action in the API; a later console spec).
- Deny rules, time windows and prohibited techniques in the form (the API accepts them).
- Model-artifact and dataset targets (Sprint 7).
- Engagement members and roles (spec 002 API; a later console spec).
