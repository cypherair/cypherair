import SwiftUI

/// Inline, search-driven recipient chooser for the Encrypt screen.
///
/// At rest it is compact: a header with the selected count + Clear All, the
/// selected recipients as removable chips, and a tag-pill strip. The full
/// candidate list is revealed only while the navigation search field is active,
/// the user is typing, or a tag filter is set — keeping the Encrypt page short.
///
/// On macOS there is no search-field focus state to gate on, so the candidate
/// list is always shown (tag pills + the navigation search field still filter it).
struct EncryptRecipientChooser: View {
    let model: EncryptScreenModel

    @Environment(\.isSearching) private var isSearching
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        selectedRecipientsContent

        tagFilterStrip

        if showsCandidateList {
            candidateListContent
        }

        if let tagSelectionSkipMessage = model.tagSelectionSkipMessage {
            Label(tagSelectionSkipMessage, systemImage: "exclamationmark.triangle.fill")
                .font(.footnote)
                .foregroundStyle(.orange)
            Button {
                model.dismissTagSelectionSkipMessage()
            } label: {
                Label(
                    String(localized: "common.dismiss", defaultValue: "Dismiss"),
                    systemImage: "xmark"
                )
            }
        }

        if !model.selectedUnverifiedContacts.isEmpty {
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
    }

    // MARK: Selected chips

    @ViewBuilder
    private var selectedRecipientsContent: some View {
        // Drive the "has a selection" UI off the raw selection, not the resolved
        // summaries — so a selection made only of stale ids (e.g. the contact was
        // deleted) still shows the count + Clear All instead of looking empty while
        // the Encrypt button stays enabled.
        if model.selectedRecipients.isEmpty {
            Text(String(localized: "encrypt.recipients.none", defaultValue: "No recipients yet"))
                .font(.footnote)
                .foregroundStyle(.secondary)
        } else {
            HStack {
                Label(selectedRecipientsSummary, systemImage: "person.2.fill")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Spacer()
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

            let selected = model.selectedRecipientSummaries
            if !selected.isEmpty {
                CypherChipFlowLayout(spacing: 8) {
                    ForEach(selected) { contact in
                        RecipientSelectedChip(
                            contact: contact,
                            defaultKeyVersion: model.defaultKeyVersion,
                            remove: {
                                withAnimation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion)) {
                                    model.toggleRecipient(contact.contactId, isOn: false)
                                }
                            }
                        )
                    }
                }
            }

            if model.hasUnavailableSelectedRecipients {
                Label(
                    String(
                        localized: "encrypt.recipients.someUnavailable",
                        defaultValue: "Some selected recipients are no longer available. Clear All to remove them."
                    ),
                    systemImage: "exclamationmark.triangle.fill"
                )
                .font(.footnote)
                .foregroundStyle(.orange)
            }
        }
    }

    // MARK: Tag pills

    @ViewBuilder
    private var tagFilterStrip: some View {
        let tagOptions = model.recipientTagOptions
        if !tagOptions.isEmpty {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 6) {
                    ForEach(tagOptions) { option in
                        CypherTagChip(
                            title: option.displayName,
                            isSelected: model.activeRecipientFilterTagId == option.tagId,
                            toggle: {
                                withAnimation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion)) {
                                    let newValue = model.activeRecipientFilterTagId == option.tagId ? nil : option.tagId
                                    model.setRecipientFilterTag(newValue)
                                }
                            }
                        )
                    }
                }
            }
        }
    }

    // MARK: Candidate list

    @ViewBuilder
    private var candidateListContent: some View {
        if let option = activeTagOption, !option.selectableContactIds.isEmpty {
            Button {
                withAnimation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion)) {
                    model.selectRecipients(withTagId: option.tagId)
                }
            } label: {
                Label(addAllTitle(for: option), systemImage: "person.2.badge.plus")
            }
            .controlSize(.small)
        }

        let candidates = model.filteredRecipientContacts
        if candidates.isEmpty {
            if model.activeRecipientFilterTagIsSkippedOnly {
                Label(
                    String(
                        localized: "encrypt.recipients.tagAllSkipped",
                        defaultValue: "Contacts with this tag need a preferred encryption key before they can receive messages."
                    ),
                    systemImage: "exclamationmark.triangle.fill"
                )
                .font(.footnote)
                .foregroundStyle(.orange)
            } else {
                Text(String(localized: "encrypt.recipients.noMatches", defaultValue: "No matching recipients"))
                    .foregroundStyle(.secondary)
            }
        } else {
            ForEach(candidates) { contact in
                Toggle(isOn: Binding(
                    get: { model.selectedRecipients.contains(contact.contactId) },
                    set: { isOn in model.toggleRecipient(contact.contactId, isOn: isOn) }
                )) {
                    HStack {
                        RecipientCompatibilityIcon(contact: contact, defaultKeyVersion: model.defaultKeyVersion)
                        VStack(alignment: .leading) {
                            Text(IdentityDisplayPresentation.displayName(contact.displayName))
                            HStack(spacing: 6) {
                                Text(contact.preferredKey.profile.displayName)
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
        }
    }

    // MARK: Helpers

    private var showsCandidateList: Bool {
        #if os(macOS)
        return true
        #else
        return isSearching
            || !ContactsSearchIndex.normalizedSearchText(model.recipientSearchText).isEmpty
            || model.activeRecipientFilterTagId != nil
        #endif
    }

    private var activeTagOption: RecipientTagSelectionOption? {
        guard let activeId = model.activeRecipientFilterTagId else { return nil }
        return model.recipientTagOptions.first { $0.tagId == activeId }
    }

    private func addAllTitle(for option: RecipientTagSelectionOption) -> String {
        String.localizedStringWithFormat(
            String(localized: "encrypt.recipients.addAllInTag", defaultValue: "Add All (%d)"),
            option.selectableContactIds.count
        )
    }

    private var selectedRecipientsSummary: String {
        String.localizedStringWithFormat(
            String(localized: "encrypt.selectedRecipients.count", defaultValue: "%d recipients selected"),
            model.selectedRecipients.count
        )
    }
}

/// The per-recipient compatibility glyph: orange downgrade warning when the
/// sender's default key is v6 but this recipient is v4 (SEIPDv1 fallback),
/// otherwise a green "compatible" check. Status is conveyed by symbol + label.
private struct RecipientCompatibilityIcon: View {
    let contact: ContactRecipientSummary
    let defaultKeyVersion: UInt8?

    var body: some View {
        if defaultKeyVersion == 6 && contact.preferredKey.keyVersion == 4 {
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

/// A removable selected-recipient chip. The whole chip is the remove control,
/// labelled "Remove <name>" for VoiceOver; the × is a visual affordance.
private struct RecipientSelectedChip: View {
    let contact: ContactRecipientSummary
    let defaultKeyVersion: UInt8?
    let remove: () -> Void

    var body: some View {
        Button(action: remove) {
            HStack(spacing: 6) {
                RecipientCompatibilityIcon(contact: contact, defaultKeyVersion: defaultKeyVersion)
                    .font(.footnote)
                Text(IdentityDisplayPresentation.displayName(contact.displayName))
                    .font(.subheadline)
                    .lineLimit(1)
                Image(systemName: "xmark.circle.fill")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .accessibilityHidden(true)
            }
            .padding(.leading, 10)
            .padding(.trailing, 8)
            .padding(.vertical, 7)
            .background(.fill.tertiary, in: Capsule())
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(
            String.localizedStringWithFormat(
                String(localized: "encrypt.recipients.remove", defaultValue: "Remove %@"),
                IdentityDisplayPresentation.displayName(contact.displayName)
            )
        )
    }
}
