# App Data / Contacts Alignment (Archived)

> **Version:** Archived v1.1  
> **Status:** Archived historical bridge. This document is no longer an active design or precedence source.  
> **Purpose:** Preserve a short record that the temporary app-data / Contacts alignment bridge has been superseded by the active Contacts and shared-framework documents.
> **Successor documents:** [PRD](../PRD.md) · [TDD](../TDD.md) · [ARCHITECTURE](../ARCHITECTURE.md) · [SECURITY](../SECURITY.md) · [PERSISTED_STATE_INVENTORY](../PERSISTED_STATE_INVENTORY.md)

This document was a temporary bridge while the Contacts docs still described an older Contacts-specific vault model.

It is now archived because the active Contacts and shared-framework docs align on:

- Contacts as a protected domain on the shared app-data framework
- `AppSessionOrchestrator` as the single grace-window and launch/resume owner
- `ProtectedDataSessionCoordinator` as the shared app-data authorization owner
- layered framework-level and domain-level recovery semantics
- Contacts adoption through App Data Phase 4 rather than a parallel vault architecture

Use the successor documents above for all current implementation and review guidance.

The detailed temporary conflict inventory that previously lived here remains available in git history if historical comparison is needed.
