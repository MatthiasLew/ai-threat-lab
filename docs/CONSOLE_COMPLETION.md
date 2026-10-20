# Console completion contract

The 2026-10-19 product direction is: prepared local tools collect evidence; the
application selects applicable checks; optional AI interprets that evidence and
explains what the user should review. AI does not write attack code, execute shell
commands, expand the approved target scope or turn candidate findings into facts.

This work supersedes the previous freeze on feature development. Accounts, keys
and live integration tests remain deferred. The established console-first order
is retained. The owner confirmed that GUI is implemented by another contributor;
this delivery contains the console and reusable application services only.

## Required user journey

1. See which prepared tools apply to a target before executing them, together with
   network destinations, data disclosures, bounds and unsupported areas.
2. Run the existing selected collectors through one coherent console workflow,
   saving verifiable evidence even when a collector fails.
3. Read a practical local summary: observations, where to look, recommended review
   and explicit gaps. An API is not necessary for this summary.
4. Prepare a bounded AI evidence packet from a saved assessment, combined report,
   single scan or batch. Preserve provenance and limitations; never upload the
   entire source tree. Preview exactly what is shared and estimate costs offline.
5. Optional AI interpretation refers to supplied observations, remains separate
   from deterministic evidence, and cannot execute tools or change findings.
6. Validate configuration and complete synthetic integration acceptance before
   account setup. Missing credentials are a future setup step, not a runtime crash.
7. Retain report/history/compare and all three approved local training workflows.

## Acceptance

- Positive, negative, malformed, partial and interrupted/failure cases have tests.
- Existing APIs and saved bundle compatibility remain intact.
- New workflows work from the installed package, without a checkout.
- Ruff, the full coverage gate, build and clean-wheel acceptance pass.
- User documentation and capability inventory distinguish implemented features,
  local verification, account setup and tests requiring real services.
- No unsupported capability is marked complete merely to satisfy a checklist.

## Beyond this contract

Arbitrary language/framework analysis, dynamic malware execution, business-logic
penetration testing, live password attacks, telephony and organization-wide
infrastructure are not implied by adding an interpretation API. They need specific
target/provider requirements and additional implementation. Subsequent console work
also supplies explicit SMTP delivery, stock-speech WAV and stock-avatar generation
adapters for approved fictional scenarios; their real account, delivery, media and
billing acceptance is still deferred. Local rehearsals and inert exports remain available.

Implementation and validation evidence will be recorded with the final delivery.
