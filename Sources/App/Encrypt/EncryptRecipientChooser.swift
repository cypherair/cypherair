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
        // Asked once per render rather than per row: it describes the whole
        // message, and every row's mark is that one answer projected onto it.
        let formatDecision = model.outgoingFormatDecision
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
                        formatState: RecipientFormatState(
                            contact: contact,
                            isAddressed: isSelected,
                            decision: formatDecision
                        ),
                        toggle: {
                            withAnimation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion)) {
                                model.toggleRecipient(contact.contactId, isOn: !isSelected)
                            }
                        }
                    )
                }
            }

            if formatDecision?.withholdsAead == true {
                messageFormatNotice
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

    /// The one place the message-level outcome is stated. A per-row mark cannot
    /// carry it alone: the Encrypt to Self copy is a recipient with no row, so a
    /// legacy self key can hold the whole message at SEIPDv1 over a chooser
    /// showing nothing but green.
    @ViewBuilder
    private var messageFormatNotice: some View {
        Label(
            String(
                localized: "encrypt.compat.messageDowngraded",
                defaultValue: "One of this message's keys has no AEAD support, so the whole message uses SEIPDv1. Recipients whose keys do support AEAD will not get it."
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

/// What the format indicator says about one row, read off the engine's decision
/// for the message as a whole.
///
/// A row the message is not addressed to has nothing to say: the indicator
/// describes an outgoing message, and that key is not in one. The two states
/// that remain mark the *causer*, never the victim — the key that costs the
/// message its AEAD is the one you can deselect to get it back, whereas the
/// recipient losing AEAD has no action to take at its own row. A message
/// addressed only to keys without AEAD support flags nobody: SEIPDv1 is what
/// those keys support, and nothing was given up.
private enum RecipientFormatState {
    case notAddressed
    case compatible
    case holdsMessageAtSeipdV1

    init(
        contact: ContactRecipientSummary,
        isAddressed: Bool,
        decision: OutgoingFormatDecision?
    ) {
        guard isAddressed, let decision else {
            self = .notAddressed
            return
        }
        self = decision.seipdV1ForcingFingerprints.contains(contact.preferredKey.fingerprint)
            ? .holdsMessageAtSeipdV1
            : .compatible
    }

    var accessibilityDescription: String? {
        switch self {
        case .notAddressed:
            nil
        case .compatible:
            String(localized: "encrypt.compat.ok", defaultValue: "Compatible")
        case .holdsMessageAtSeipdV1:
            String(
                localized: "encrypt.compat.limitsMessageFormat",
                defaultValue: "Holds this message at SEIPDv1, with no AEAD for the other recipients"
            )
        }
    }
}

/// A composed VoiceOver label for a recipient row: name, suite, plus the format
/// state and the unverified status when they apply. Keeps those cues audible
/// (following the comma-separated idiom used elsewhere in the app); the row
/// separately announces its selected state.
private func recipientAccessibilityLabel(
    _ contact: ContactRecipientSummary,
    formatState: RecipientFormatState
) -> String {
    var parts = [
        IdentityDisplayPresentation.displayName(contact.displayName),
        contact.preferredKey.suite.contactKeyKindDisplayName
    ]
    if let formatDescription = formatState.accessibilityDescription {
        parts.append(formatDescription)
    }
    if !contact.isPreferredKeyVerified {
        parts.append(String(localized: "encrypt.contact.unverified", defaultValue: "Unverified"))
    }
    return parts.joined(separator: ", ")
}

/// The per-recipient compatibility glyph. A row the message is not addressed to
/// keeps the slot but shows nothing, so selecting a recipient never shifts the
/// rest of the row. The state is spoken as part of the row's composed label, so
/// the symbol itself stays out of the accessibility tree.
private struct RecipientCompatibilityIcon: View {
    let formatState: RecipientFormatState

    var body: some View {
        Group {
            switch formatState {
            case .notAddressed:
                Image(systemName: "checkmark.circle.fill")
                    .hidden()
            case .compatible:
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.green)
            case .holdsMessageAtSeipdV1:
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            }
        }
        .accessibilityHidden(true)
    }
}

/// Shared identity content for a recipient row: compatibility glyph, the display
/// name (wraps rather than truncating so long names keep their identity info), the
/// suite, and an Unverified badge when applicable.
private struct RecipientRowContent: View {
    let contact: ContactRecipientSummary
    let formatState: RecipientFormatState

    var body: some View {
        HStack {
            RecipientCompatibilityIcon(formatState: formatState)
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
    let formatState: RecipientFormatState
    let toggle: () -> Void

    var body: some View {
        Button(action: toggle) {
            HStack {
                RecipientRowContent(contact: contact, formatState: formatState)
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
        .accessibilityLabel(recipientAccessibilityLabel(contact, formatState: formatState))
        .accessibilityAddTraits(isSelected ? .isSelected : [])
        .accessibilityIdentifier("encrypt.recipient.row")
    }
}
