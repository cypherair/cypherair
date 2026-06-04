import SwiftUI

/// Inline recipient chooser for the Encrypt screen.
///
/// Mirrors the Contacts screen: candidate recipients are shown by default, with a
/// horizontal tag-filter strip and the navigation search field refining the list —
/// tags and search filter the list, they never gate whether recipients appear. The
/// current selection is always visible as a pinned "Selected" group above the
/// candidates, so a chosen recipient stays visible even when a filter would hide it.
/// Behaves identically on iOS, macOS, and visionOS.
struct EncryptRecipientChooser: View {
    let model: EncryptScreenModel

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        tagFilterStrip

        selectedRecipientsContent

        candidateListContent

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

    // MARK: Tag filter strip

    @ViewBuilder
    private var tagFilterStrip: some View {
        let tagFilters = model.recipientTagFilters
        if !tagFilters.isEmpty {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 6) {
                    ForEach(tagFilters) { tag in
                        CypherTagChip(
                            title: tag.displayName,
                            isSelected: model.isRecipientTagFilterSelected(tag.tagId),
                            toggle: {
                                withAnimation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion)) {
                                    model.toggleRecipientTagFilter(tag.tagId)
                                }
                            }
                        )
                    }

                    if !model.selectedRecipientTagFilters.isEmpty {
                        Button {
                            withAnimation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion)) {
                                model.clearRecipientTagFilters()
                            }
                        } label: {
                            Label(
                                String(localized: "encrypt.recipients.clearTagFilters", defaultValue: "Clear"),
                                systemImage: "xmark.circle"
                            )
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    }
                }
            }
        }
    }

    // MARK: Selected group

    @ViewBuilder
    private var selectedRecipientsContent: some View {
        let selected = model.selectedRecipientSummaries
        if !selected.isEmpty {
            HStack {
                Label(selectedRecipientsSummary(count: selected.count), systemImage: "person.2.fill")
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

            ForEach(selected) { contact in
                SelectedRecipientRow(
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

    // MARK: Candidate list

    @ViewBuilder
    private var candidateListContent: some View {
        let candidates = model.addableRecipientContacts
        if candidates.isEmpty {
            emptyCandidatesLabel
        } else {
            if candidates.count > 1 {
                Button {
                    withAnimation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion)) {
                        model.addAllVisibleRecipients()
                    }
                } label: {
                    Label(addAllShownTitle(count: candidates.count), systemImage: "person.2.badge.plus")
                }
                .controlSize(.small)
            }

            ForEach(candidates) { contact in
                RecipientCandidateRow(
                    contact: contact,
                    defaultKeyVersion: model.defaultKeyVersion,
                    add: {
                        withAnimation(CypherMotion.quickEaseOut(reduceMotion: reduceMotion)) {
                            model.toggleRecipient(contact.contactId, isOn: true)
                        }
                    }
                )
            }
        }
    }

    @ViewBuilder
    private var emptyCandidatesLabel: some View {
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
        } else if model.hasActiveRecipientSearchOrFilter {
            Text(String(localized: "encrypt.recipients.noMatches", defaultValue: "No matching recipients"))
                .foregroundStyle(.secondary)
        } else {
            Text(String(localized: "encrypt.recipients.allAdded", defaultValue: "All recipients added"))
                .foregroundStyle(.secondary)
        }
    }

    // MARK: Helpers

    private func addAllShownTitle(count: Int) -> String {
        String.localizedStringWithFormat(
            String(localized: "encrypt.recipients.addAllShown", defaultValue: "Add All Shown (%d)"),
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
/// downgrade/verification cues audible on both selected and candidate rows
/// (following the comma-separated idiom used elsewhere in the app).
private func recipientAccessibilityLabel(
    _ contact: ContactRecipientSummary,
    defaultKeyVersion: UInt8?
) -> String {
    var parts = [
        IdentityDisplayPresentation.displayName(contact.displayName),
        contact.preferredKey.profile.displayName
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

/// A selected recipient as a full-width row with a trailing remove control. The
/// identity content is announced as a single composed label; the remove control is
/// a separate, explicitly-labelled element.
private struct SelectedRecipientRow: View {
    let contact: ContactRecipientSummary
    let defaultKeyVersion: UInt8?
    let remove: () -> Void

    var body: some View {
        HStack {
            RecipientRowContent(contact: contact, defaultKeyVersion: defaultKeyVersion)
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(recipientAccessibilityLabel(contact, defaultKeyVersion: defaultKeyVersion))
            Spacer()
            Button(action: remove) {
                Image(systemName: "xmark.circle.fill")
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.borderless)
            .accessibilityLabel(
                String.localizedStringWithFormat(
                    String(localized: "encrypt.recipients.remove", defaultValue: "Remove %@"),
                    IdentityDisplayPresentation.displayName(contact.displayName)
                )
            )
        }
        .accessibilityIdentifier("encrypt.recipient.selected")
    }
}

/// An addable candidate as a full-width tap-to-add row. The whole row is the add
/// control; VoiceOver announces the composed identity label plus an "adds" hint.
private struct RecipientCandidateRow: View {
    let contact: ContactRecipientSummary
    let defaultKeyVersion: UInt8?
    let add: () -> Void

    var body: some View {
        Button(action: add) {
            HStack {
                RecipientRowContent(contact: contact, defaultKeyVersion: defaultKeyVersion)
                Spacer()
                Image(systemName: "plus.circle")
                    .foregroundStyle(.tint)
                    .accessibilityHidden(true)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(recipientAccessibilityLabel(contact, defaultKeyVersion: defaultKeyVersion))
        .accessibilityHint(String(localized: "encrypt.recipients.addHint", defaultValue: "Adds this recipient"))
        .accessibilityIdentifier("encrypt.recipient.candidate")
    }
}
