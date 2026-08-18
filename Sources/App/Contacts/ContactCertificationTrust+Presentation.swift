import SwiftUI

// The one place certification and trust are put into words. Three surfaces show
// this vocabulary — the key summary, the contact roll-up and the certification
// screen — and they read from here so that a claim cannot be worded more
// strongly on one screen than on another.
//
// The colour language is part of the claim. Green is reserved for trust the user
// anchored themselves; a vouch reads in its own colour because it is somebody
// else's word; a signature that merely verifies gets no colour at all, because
// "this signature is valid" is a fact about bytes and must never look like an
// endorsement.

extension ContactKeyTrust.Anchor {
    var badgeTitle: String {
        switch self {
        case .verifiedByUser:
            String(localized: "contacttrust.anchor.verifiedByYou", defaultValue: "Verified by You")
        case .vouched(let voucher, let otherVoucherCount):
            otherVoucherCount > 0
                ? String(
                    localized: "contacttrust.anchor.vouchedPlus",
                    defaultValue: "Vouched by \(voucher.displayName) +\(otherVoucherCount)"
                )
                : String(
                    localized: "contacttrust.anchor.vouched",
                    defaultValue: "Vouched by \(voucher.displayName)"
                )
        case .unanchored:
            String(localized: "contacttrust.anchor.unanchored", defaultValue: "Unverified")
        }
    }

    var badgeColor: Color {
        switch self {
        case .verifiedByUser:
            .green
        case .vouched:
            .blue
        case .unanchored:
            .orange
        }
    }

    var badgeSystemImage: String {
        switch self {
        case .verifiedByUser:
            "checkmark.shield.fill"
        case .vouched:
            "person.crop.circle.badge.checkmark"
        case .unanchored:
            "exclamationmark.triangle.fill"
        }
    }
}

extension ContactKeyTrust {
    /// Reads out every contact currently vouching for the key. Plain naming, no
    /// count games: the user should be able to see exactly whose word this is.
    var vouchersDescription: String {
        vouchers
            .map(\.displayName)
            .formatted(.list(type: .and))
    }
}

extension ContactCertificationProjection.SignatureState {
    var badgeTitle: String {
        switch self {
        case .absent:
            String(localized: "contactcertification.signatures.absent", defaultValue: "None")
        case .valid:
            String(localized: "contactcertification.signatures.valid", defaultValue: "Signatures Valid")
        case .invalidOrStale:
            String(localized: "contactcertification.signatures.invalid", defaultValue: "Invalid or Stale")
        case .revalidationNeeded:
            String(
                localized: "contactcertification.signatures.revalidation",
                defaultValue: "Revalidation Needed"
            )
        }
    }

    var badgeColor: Color {
        switch self {
        case .absent, .valid:
            .secondary
        case .invalidOrStale:
            .red
        case .revalidationNeeded:
            .orange
        }
    }
}

extension ContactCertificationSignerRole {
    var badgeTitle: String {
        switch self {
        case .you:
            String(localized: "contactcertification.signer.you", defaultValue: "Your Key")
        case .targetKeyItself:
            String(localized: "contactcertification.signer.itself", defaultValue: "This Key Itself")
        case .contact(let signer):
            if signer.carriesVouchingWeight {
                String(
                    localized: "contactcertification.signer.verifiedContact",
                    defaultValue: "Verified Contact"
                )
            } else if signer.isVerifiedByUser {
                String(
                    localized: "contactcertification.signer.revokedContact",
                    defaultValue: "Verified Contact, Revoked Key"
                )
            } else {
                String(
                    localized: "contactcertification.signer.unverifiedContact",
                    defaultValue: "Unverified Contact"
                )
            }
        case .unknown:
            String(localized: "contactcertification.signer.unknown", defaultValue: "Unknown Signer")
        }
    }

    var badgeColor: Color {
        switch self {
        case .contact(let signer):
            signer.carriesVouchingWeight ? .blue : .orange
        case .you:
            .secondary
        case .targetKeyItself, .unknown:
            .orange
        }
    }

    var displayName: String {
        switch self {
        case .you(_, let displayName):
            displayName
        case .contact(let signer):
            IdentityDisplayPresentation.displayName(signer.displayName)
        case .targetKeyItself(let fingerprint), .unknown(let fingerprint):
            IdentityPresentation.shortKeyId(from: fingerprint)
        }
    }

    var secondaryText: String? {
        guard case .contact(let signer) = self else {
            return nil
        }
        return signer.secondaryText
    }

    /// What this signer's word is worth, stated outright. Every role says so —
    /// including the ones that count for nothing, because "a valid signature
    /// exists" is exactly the fact a reader is most likely to over-read.
    var weightNote: String {
        switch self {
        case .you:
            String(
                localized: "contactcertification.signer.you.note",
                defaultValue: "You made this certification with your own key. It records what you did, not anyone else's word about this contact."
            )
        case .targetKeyItself:
            String(
                localized: "contactcertification.signer.itself.note",
                defaultValue: "This is the key signing itself. Every OpenPGP certificate carries such a signature, and it attests nothing beyond what the certificate already claims about itself."
            )
        case .contact(let signer):
            if signer.carriesVouchingWeight {
                String(
                    localized: "contactcertification.signer.verifiedContact.note",
                    defaultValue: "You verified this contact's fingerprint yourself, so their certification vouches for this key. Withdrawing that verification removes this vouch."
                )
            } else if signer.isVerifiedByUser {
                String(
                    localized: "contactcertification.signer.revokedContact.note",
                    defaultValue: "This contact's key has been revoked, so nothing it signed counts any more."
                )
            } else {
                String(
                    localized: "contactcertification.signer.unverifiedContact.note",
                    defaultValue: "You have not verified this contact's fingerprint, so their certification carries no weight here."
                )
            }
        case .unknown:
            String(
                localized: "contactcertification.signer.unknown.note",
                defaultValue: "No key you hold matches this signer, so there is nothing the app can tell you about who they are."
            )
        }
    }
}
