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
        let formatPreview = model.outgoingMessageFormatPreview
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
                        formatPreview: formatPreview,
                        toggle: {
                            withAnimation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion)) {
                                model.toggleRecipient(contact.contactId, isOn: !isSelected)
                            }
                        }
                    )
                }
            }

            if formatPreview.downgradesAeadCapableRecipients {
                formatDowngradeLabel
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

    /// The message-level half of the format story. A per-row glyph can only ever
    /// point at a row, and the certificate that forces the fallback may be the
    /// Encrypt to Self copy, which has no row — so the outcome is also stated
    /// once, for the whole message.
    @ViewBuilder
    private var formatDowngradeLabel: some View {
        Label(
            String(
                localized: "encrypt.compat.messageDowngraded",
                defaultValue: "Encrypted to at least one v4 key, so this message will use SEIPDv1 — recipients whose keys support AEAD will not get it."
            ),
            systemImage: "exclamationmark.triangle.fill"
        )
        .font(.footnote)
        .foregroundStyle(.orange)
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

/// A composed VoiceOver label for a recipient row: name, suite, plus the format
/// warning and the unverified status when they apply. Keeps the format and
/// verification cues audible (following the comma-separated idiom used elsewhere
/// in the app); the row separately announces its selected state.
private func recipientAccessibilityLabel(
    _ contact: ContactRecipientSummary,
    formatPreview: OutgoingMessageFormatPreview
) -> String {
    var parts = [
        IdentityDisplayPresentation.displayName(contact.displayName),
        contact.preferredKey.suite.contactKeyKindDisplayName
    ]
    if formatPreview.limitsFormat(recipientKeyVersion: contact.preferredKey.keyVersion) {
        parts.append(
            String(localized: "encrypt.compat.limitsMessageFormat", defaultValue: "Limits this message to SEIPDv1")
        )
    }
    if !contact.isPreferredKeyVerified {
        parts.append(String(localized: "encrypt.contact.unverified", defaultValue: "Unverified"))
    }
    return parts.joined(separator: ", ")
}

/// The per-recipient compatibility glyph: an orange warning when this recipient's
/// key is what holds the message at SEIPDv1 — its v4 certificate alongside at
/// least one AEAD-capable one — otherwise a green "compatible" check. A message
/// addressed only to v4 keys gives nothing up and stays green.
///
/// The predicate reads the whole message's format decision, so a row that is not
/// selected yet answers the same question honestly: adding it is what would cost
/// the message its AEAD. Status is conveyed by symbol + label.
private struct RecipientCompatibilityIcon: View {
    let contact: ContactRecipientSummary
    let formatPreview: OutgoingMessageFormatPreview

    var body: some View {
        if formatPreview.limitsFormat(recipientKeyVersion: contact.preferredKey.keyVersion) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .accessibilityLabel(
                    String(
                        localized: "encrypt.compat.limitsMessageFormat",
                        defaultValue: "Limits this message to SEIPDv1"
                    )
                )
        } else {
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(.green)
                .accessibilityLabel(String(localized: "encrypt.compat.ok", defaultValue: "Compatible"))
        }
    }
}

/// Shared identity content for a recipient row: compatibility glyph, the display
/// name (wraps rather than truncating so long names keep their identity info), the
/// suite, and an Unverified badge when applicable.
private struct RecipientRowContent: View {
    let contact: ContactRecipientSummary
    let formatPreview: OutgoingMessageFormatPreview

    var body: some View {
        HStack {
            RecipientCompatibilityIcon(contact: contact, formatPreview: formatPreview)
            VStack(alignment: .leading, spacing: 2) {
                Text(IdentityDisplayPresentation.displayName(contact.displayName))
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 6) {
                    Text(contact.preferredKey.suite.contactKeyKindDisplayName)
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
    let formatPreview: OutgoingMessageFormatPreview
    let toggle: () -> Void

    var body: some View {
        Button(action: toggle) {
            HStack {
                RecipientRowContent(contact: contact, formatPreview: formatPreview)
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
        .accessibilityLabel(recipientAccessibilityLabel(contact, formatPreview: formatPreview))
        .accessibilityAddTraits(isSelected ? .isSelected : [])
        .accessibilityIdentifier("encrypt.recipient.row")
    }
}
