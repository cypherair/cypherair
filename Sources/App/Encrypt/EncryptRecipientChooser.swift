import SwiftUI

/// Inline recipient chooser for the Encrypt screen.
///
/// A single, spatially-stable list of recipients: every encryptable recipient
/// matching the search field and tag filters is shown as one row with an in-place
/// selection toggle (an empty circle that crossfades to a filled checkmark, the same
/// idiom as Contacts tag-member editing). Selecting a recipient only flips its check
/// glyph — rows never move — because the list is ordered independently of the
/// selection. A header shows the running selected count; tags and search refine the
/// list but never gate whether recipients appear. Behaves identically on iOS, macOS,
/// and visionOS.
struct EncryptRecipientChooser: View {
    let model: EncryptScreenModel

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        // Hoisted once per render so the per-row selection check and the tag strip
        // don't re-project the recipient/tag lists for every element.
        let recipients = model.filteredRecipientContacts
        let selectedIds = model.selectedRecipients
        let tags = model.recipientTagFilters
        let selectedTagIds = model.selectedRecipientTagFilterIds
        let selectedCount = model.effectiveRecipientContactIds.count
        let hiddenSelectedCount = model.hiddenSelectedRecipientCount
        let addableCount = recipients.reduce(into: 0) { count, contact in
            count += selectedIds.contains(contact.contactId) ? 0 : 1
        }

        Group {
            if !tags.isEmpty {
                TagFilterStrip(
                    tags: tags,
                    selectedIds: selectedTagIds,
                    clearTitle: String(localized: "encrypt.recipients.clearTagFilters", defaultValue: "Clear"),
                    toggle: { model.toggleRecipientTagFilter($0) },
                    clear: { model.clearRecipientTagFilters() }
                )
            }

            if model.hasAvailableRecipients {
                recipientCountHeader(selectedCount: selectedCount)
                if addableCount > 0 {
                    selectAllShownButton(count: addableCount)
                }
            }

            if hiddenSelectedCount > 0 {
                hiddenSelectedNotice(count: hiddenSelectedCount)
            }

            if model.hasStaleSelectedRecipients {
                staleRecipientsWarning
            }

            if recipients.isEmpty {
                emptyState
            } else {
                ForEach(recipients) { contact in
                    let isSelected = selectedIds.contains(contact.contactId)
                    RecipientToggleRow(
                        contact: contact,
                        isSelected: isSelected,
                        defaultKeyVersion: model.defaultKeyVersion,
                        toggle: {
                            withAnimation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion)) {
                                model.toggleRecipient(contact.contactId, isOn: !isSelected)
                            }
                        }
                    )
                }
            }

            if !model.selectedUnverifiedContacts.isEmpty {
                unverifiedWarningLabel
            }
        }
        .animation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion), value: recipients.map(\.contactId))
        .animation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion), value: selectedTagIds)
        .animation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion), value: model.hasActiveRecipientSearchOrFilter)
    }

    // MARK: Header + bulk actions

    @ViewBuilder
    private func recipientCountHeader(selectedCount: Int) -> some View {
        HStack {
            Label(selectedRecipientsSummary(count: selectedCount), systemImage: "person.2.fill")
                .font(.footnote)
                .foregroundStyle(.secondary)
            Spacer()
            if selectedCount > 0 {
                Button {
                    withAnimation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion)) {
                        model.clearRecipients()
                    }
                } label: {
                    Label(
                        String(localized: "encrypt.clearRecipients", defaultValue: "Clear All"),
                        systemImage: "xmark.circle"
                    )
                }
                .controlSize(.small)
            }
        }
    }

    @ViewBuilder
    private func selectAllShownButton(count: Int) -> some View {
        Button {
            withAnimation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion)) {
                model.addAllVisibleRecipients()
            }
        } label: {
            Label(selectAllShownTitle(count: count), systemImage: "person.2.badge.plus")
        }
        .controlSize(.small)
    }

    // MARK: Filter-hidden selection surface

    @ViewBuilder
    private func hiddenSelectedNotice(count: Int) -> some View {
        HStack {
            Label(hiddenSelectedSummary(count: count), systemImage: "eye.slash")
                .font(.footnote)
                .foregroundStyle(.secondary)
            Spacer()
            Button {
                withAnimation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion)) {
                    model.clearRecipientSearchAndFilters()
                }
            } label: {
                Label(
                    String(localized: "encrypt.recipients.showAll", defaultValue: "Show All"),
                    systemImage: "eye"
                )
            }
            .controlSize(.small)
        }
    }

    // MARK: Stale-selection surface

    @ViewBuilder
    private var staleRecipientsWarning: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label(
                String(
                    localized: "encrypt.recipients.staleWarning",
                    defaultValue: "Some selected recipients are no longer available."
                ),
                systemImage: "exclamationmark.triangle.fill"
            )
            .font(.footnote)
            .foregroundStyle(.orange)

            Button {
                withAnimation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion)) {
                    model.removeStaleRecipients()
                }
            } label: {
                Label(
                    String(localized: "encrypt.recipients.removeStale", defaultValue: "Remove unavailable recipients"),
                    systemImage: "person.crop.circle.badge.xmark"
                )
            }
            .controlSize(.small)
        }
    }

    // MARK: Empty + unverified

    @ViewBuilder
    private var emptyState: some View {
        if !model.hasAvailableRecipients {
            Label(
                String(
                    localized: "encrypt.recipients.noneAvailable",
                    defaultValue: "No recipients available yet. Add a contact's public key to encrypt to them."
                ),
                systemImage: "person.crop.circle.badge.questionmark"
            )
            .font(.footnote)
            .foregroundStyle(.secondary)
        } else {
            Text(String(localized: "encrypt.recipients.noMatches", defaultValue: "No matching recipients"))
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var unverifiedWarningLabel: some View {
        Label(
            String(
                localized: "encrypt.unverified.warning",
                defaultValue: "One or more selected recipients are still unverified. Verify their fingerprints before relying on them."
            ),
            systemImage: "exclamationmark.triangle.fill"
        )
        .font(.footnote)
        .foregroundStyle(.orange)
    }

    // MARK: Helpers

    private func selectAllShownTitle(count: Int) -> String {
        String.localizedStringWithFormat(
            String(localized: "encrypt.recipients.selectAllShown", defaultValue: "Select All Shown (%d)"),
            count
        )
    }

    private func selectedRecipientsSummary(count: Int) -> String {
        // Count is interpolated into the localized lookup so the String Catalog can
        // resolve the grammatically-correct plural (e.g. "1 recipient selected").
        String(
            localized: "encrypt.selectedRecipients.count",
            defaultValue: "\(count) recipients selected"
        )
    }

    private func hiddenSelectedSummary(count: Int) -> String {
        // Count interpolated so the String Catalog resolves the correct plural.
        String(
            localized: "encrypt.recipients.hiddenByFilter",
            defaultValue: "\(count) selected recipients hidden by the current filter"
        )
    }
}

/// Single source of truth for the SEIPDv1-downgrade rule: a v6 sender default key
/// encrypting to a v4 recipient falls back to SEIPDv1 (no AEAD).
enum RecipientCompatibility {
    static func isSeipdV1Downgrade(senderDefaultKeyVersion: UInt8?, recipientKeyVersion: UInt8) -> Bool {
        senderDefaultKeyVersion == 6 && recipientKeyVersion == 4
    }
}

/// A composed VoiceOver label for a recipient row: name, profile, plus the SEIPDv1
/// downgrade warning and the unverified status when they apply. Keeps the
/// downgrade/verification cues audible (following the comma-separated idiom used
/// elsewhere in the app); the row separately announces its selected state.
private func recipientAccessibilityLabel(
    _ contact: ContactRecipientSummary,
    defaultKeyVersion: UInt8?
) -> String {
    var parts = [
        IdentityDisplayPresentation.displayName(contact.displayName),
        contact.preferredKey.profile.contactKeyKindDisplayName
    ]
    if RecipientCompatibility.isSeipdV1Downgrade(
        senderDefaultKeyVersion: defaultKeyVersion,
        recipientKeyVersion: contact.preferredKey.keyVersion
    ) {
        parts.append(String(localized: "encrypt.compat.downgrade", defaultValue: "Format downgrade to SEIPDv1"))
    }
    if !contact.isPreferredKeyVerified {
        parts.append(String(localized: "encrypt.contact.unverified", defaultValue: "Unverified"))
    }
    return parts.joined(separator: ", ")
}

/// The per-recipient compatibility glyph: orange downgrade warning when the
/// sender's default key is v6 but this recipient is v4 (SEIPDv1 fallback),
/// otherwise a green "compatible" check. Status is conveyed by symbol + label.
private struct RecipientCompatibilityIcon: View {
    let contact: ContactRecipientSummary
    let defaultKeyVersion: UInt8?

    var body: some View {
        if RecipientCompatibility.isSeipdV1Downgrade(
            senderDefaultKeyVersion: defaultKeyVersion,
            recipientKeyVersion: contact.preferredKey.keyVersion
        ) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .accessibilityLabel(String(localized: "encrypt.compat.downgrade", defaultValue: "Format downgrade to SEIPDv1"))
        } else {
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(.green)
                .accessibilityLabel(String(localized: "encrypt.compat.ok", defaultValue: "Compatible"))
        }
    }
}

/// Shared identity content for a recipient row: compatibility glyph, the display
/// name (wraps rather than truncating so long names keep their identity info), the
/// profile, and an Unverified badge when applicable.
private struct RecipientRowContent: View {
    let contact: ContactRecipientSummary
    let defaultKeyVersion: UInt8?

    var body: some View {
        HStack {
            RecipientCompatibilityIcon(contact: contact, defaultKeyVersion: defaultKeyVersion)
            VStack(alignment: .leading, spacing: 2) {
                Text(IdentityDisplayPresentation.displayName(contact.displayName))
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 6) {
                    Text(contact.preferredKey.profile.contactKeyKindDisplayName)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    if !contact.isPreferredKeyVerified {
                        CypherStatusBadge(
                            title: String(localized: "encrypt.contact.unverified", defaultValue: "Unverified"),
                            color: .orange
                        )
                    }
                }
            }
        }
    }
}

/// A recipient as a full-width row whose whole surface toggles selection. The
/// trailing glyph crossfades an empty circle into a filled checkmark in place, so
/// selecting a recipient never moves the row. VoiceOver announces the composed
/// identity label plus the selected/unselected trait.
private struct RecipientToggleRow: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let contact: ContactRecipientSummary
    let isSelected: Bool
    let defaultKeyVersion: UInt8?
    let toggle: () -> Void

    var body: some View {
        Button(action: toggle) {
            HStack {
                RecipientRowContent(contact: contact, defaultKeyVersion: defaultKeyVersion)
                Spacer()
                ZStack {
                    Image(systemName: "circle")
                        .foregroundStyle(Color.secondary)
                        .opacity(isSelected ? 0 : 1)
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(Color.accentColor)
                        .opacity(isSelected ? 1 : 0)
                }
                .imageScale(.large)
                .animation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion), value: isSelected)
                .accessibilityHidden(true)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(recipientAccessibilityLabel(contact, defaultKeyVersion: defaultKeyVersion))
        .accessibilityAddTraits(isSelected ? .isSelected : [])
        .accessibilityIdentifier("encrypt.recipient.row")
    }
}
