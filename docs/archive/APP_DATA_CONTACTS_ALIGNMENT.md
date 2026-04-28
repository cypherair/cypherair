# App Data / Contacts Alignment (Archived)

> **Version:** Archived v1.1  
> **Status:** Archived historical bridge. This document is no longer an active design or precedence source.  
> **Purpose:** Preserve a short record that the temporary app-data / Contacts alignment bridge has been superseded by the active Contacts and app-data documents.  
> **Successor documents:** [ARCHITECTURE](../ARCHITECTURE.md) · [SECURITY](../SECURITY.md) · [TDD](../TDD.md) · [APP_DATA_MIGRATION_GUIDE](../APP_DATA_MIGRATION_GUIDE.md) · [APP_DATA_ROADMAP_STATUS](../APP_DATA_ROADMAP_STATUS.md) · [CONTACTS_PRD](../CONTACTS_PRD.md) · [CONTACTS_TDD](../CONTACTS_TDD.md)

This document was a temporary bridge while the Contacts docs still described an older Contacts-specific vault model.

It is now archived because the active Contacts and app-data docs align on:

- Contacts as a protected domain on the shared app-data framework
- `AppSessionOrchestrator` as the single grace-window and launch/resume owner
- `ProtectedDataSessionCoordinator` as the shared app-data authorization owner
- layered framework-level and domain-level recovery semantics
- Contacts adoption through App Data Phase 4 rather than a parallel vault architecture

Use the successor documents above for all current implementation and review guidance.

The detailed temporary conflict inventory that previously lived here remains available in git history if historical comparison is needed.
