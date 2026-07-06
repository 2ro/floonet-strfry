// Grin payment-proof verification for name transfers (spec section 5, checks
// 6-8). This is a faithful port of grin-proof-watcher/src/proof.rs and
// GoblinPay's gp-wallet/src/proof.rs: bech32 grin1/tgrin1 slatepack-address
// decode, the big-endian amount encoding, the exact 73-byte
// `payment_proof_message` layout (`amount_u64_BE || excess(33) || sender(32)`),
// and ed25519 signature verification. The bytes are identical to what the
// buyer's Grin wallet signed, so we never hand-roll ed25519 and never invent a
// message format: both mirror libwallet's `payment_proof_message` /
// `verify_payment_proof` byte for byte.
//
// Unlike the watcher (which tolerates an absent sender signature for flows that
// omit it), a transfer claim requires BOTH signatures to verify: the receiver
// under `recipient_address`, the sender under `sender_address`, over the same
// message (spec section 5, check 6).

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;

/// Grin slatepack address human-readable prefixes (mainnet / floonet).
const GRIN_HRPS: [&str; 2] = ["grin", "tgrin"];

/// Normalize a slatepack address for equality comparison.
pub fn normalize_grin_address(address: &str) -> String {
    address.trim().to_lowercase()
}

/// Decode a grin1/tgrin1 slatepack address to its raw 32-byte ed25519 public
/// key, or `None` if it is not a valid Grin slatepack address. Classic bech32
/// (not bech32m), matching Grin's `SlatepackAddress`.
pub fn decode_grin_address(address: &str) -> Option<[u8; 32]> {
    use bech32::FromBase32;
    let norm = normalize_grin_address(address);
    let (hrp, data, _variant) = bech32::decode(&norm).ok()?;
    if !GRIN_HRPS.contains(&hrp.as_str()) {
        return None;
    }
    let bytes = Vec::<u8>::from_base32(&data).ok()?;
    bytes.try_into().ok()
}

/// Encode a 32-byte ed25519 public key as a grin1/tgrin1 slatepack address.
/// The authority only ever decodes addresses in production; this is the
/// reference/test helper for building proofs (used by the integration tests).
pub fn grin_address_from_pubkey(pubkey: &[u8; 32], hrp: &str) -> String {
    use bech32::{ToBase32, Variant};
    bech32::encode(hrp, pubkey.to_base32(), Variant::Bech32).expect("valid hrp")
}

/// Big-endian u64 encoding of a nanogrin amount, matching Grin's
/// `payment_proof_message`.
pub fn amount_to_be_u64(amount: u64) -> [u8; 8] {
    amount.to_be_bytes()
}

/// The exact 73 bytes the receiver and sender sign over:
/// `BE_u64(amount) || excess(33) || sender(32)`. Returns `None` when the excess
/// hex is not exactly 33 bytes. Mirrors libwallet `payment_proof_message`.
pub fn payment_proof_message(
    amount: u64,
    excess_hex: &str,
    sender_pubkey: &[u8; 32],
) -> Option<Vec<u8>> {
    let excess = hex::decode(excess_hex).ok()?;
    if excess.len() != 33 {
        return None;
    }
    let mut msg = Vec::with_capacity(8 + 33 + 32);
    msg.extend_from_slice(&amount_to_be_u64(amount));
    msg.extend_from_slice(&excess);
    msg.extend_from_slice(sender_pubkey);
    Some(msg)
}

/// A Grin payment proof parsed from the wallet owner-API JSON shape: exactly the
/// six fields `retrieve_payment_proof` exports (`amount`, `excess`,
/// `recipient_address`, `recipient_sig`, `sender_address`, `sender_sig`).
#[derive(Debug, Clone)]
pub struct ParsedPaymentProof {
    /// Amount in integer nanogrin.
    pub amount: u64,
    /// Kernel excess (commitment), 33-byte hex, lowercased.
    pub excess_hex: String,
    pub recipient_address: String,
    pub recipient_sig_hex: String,
    pub sender_address: String,
    pub sender_sig_hex: String,
}

fn value_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

/// Parse a Grin payment proof from the six-field owner-API JSON object. All six
/// fields are required for a transfer claim; returns `None` on any shape
/// mismatch. `amount` is accepted as a JSON string (the wallet's export shape)
/// or a non-negative number.
pub fn parse_payment_proof(value: &Value) -> Option<ParsedPaymentProof> {
    let obj = value.as_object()?;

    let amount_raw = obj.get("amount")?;
    let excess = obj.get("excess").and_then(value_str)?;
    let recipient_address = obj.get("recipient_address").and_then(value_str)?;
    let recipient_sig = obj.get("recipient_sig").and_then(value_str)?;
    let sender_address = obj.get("sender_address").and_then(value_str)?;
    let sender_sig = obj.get("sender_sig").and_then(value_str)?;

    let amount: u64 = match amount_raw {
        Value::Number(n) => n.as_u64()?,
        Value::String(s) => s.trim().parse::<u64>().ok()?,
        _ => return None,
    };

    Some(ParsedPaymentProof {
        amount,
        excess_hex: excess.to_lowercase(),
        recipient_address,
        recipient_sig_hex: recipient_sig.to_lowercase(),
        sender_address,
        sender_sig_hex: sender_sig.to_lowercase(),
    })
}

/// Verify BOTH proof signatures over the canonical 73-byte message: the
/// recipient signature under `recipient_address` and the sender signature under
/// `sender_address` (spec section 5, check 6). Returns `false` on any malformed
/// field, bad address, wrong signature length, or verification failure - a
/// proof that does not fully verify is simply not a valid proof.
pub fn verify_signatures(proof: &ParsedPaymentProof) -> bool {
    let Some(recipient_pub) = decode_grin_address(&proof.recipient_address) else {
        return false;
    };
    let Some(sender_pub) = decode_grin_address(&proof.sender_address) else {
        return false;
    };
    let Some(msg) = payment_proof_message(proof.amount, &proof.excess_hex, &sender_pub) else {
        return false;
    };
    let recipient_sig = match hex::decode(&proof.recipient_sig_hex) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let sender_sig = match hex::decode(&proof.sender_sig_hex) {
        Ok(s) => s,
        Err(_) => return false,
    };
    verify_ed25519(&recipient_pub, &msg, &recipient_sig)
        && verify_ed25519(&sender_pub, &msg, &sender_sig)
}

/// Verify an ed25519 signature, non-strict, matching Grin's
/// `verify_payment_proof` (`DalekPublicKey::verify`).
fn verify_ed25519(pubkey: &[u8; 32], message: &[u8], sig: &[u8]) -> bool {
    let vk = match VerifyingKey::from_bytes(pubkey) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    let sig_arr: [u8; 64] = match sig.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(&sig_arr);
    vk.verify(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn keypair() -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    /// Build a fully-signed six-field proof JSON value, exactly as the wallet
    /// exports it: sign the real 73-byte message with real ed25519 keys.
    fn make_proof(amount: u64) -> (Value, String) {
        let (recipient_sk, recipient_pub) = keypair();
        let (sender_sk, sender_pub) = keypair();

        // 33-byte kernel excess (Pedersen-commitment-shaped fixture).
        let mut excess = [0u8; 33];
        excess[..32].copy_from_slice(&recipient_pub);
        excess[32] = 0x08;
        let excess_hex = hex::encode(excess);

        let msg = payment_proof_message(amount, &excess_hex, &sender_pub).unwrap();
        let recipient_sig = hex::encode(recipient_sk.sign(&msg).to_bytes());
        let sender_sig = hex::encode(sender_sk.sign(&msg).to_bytes());
        let recipient_address = grin_address_from_pubkey(&recipient_pub, "grin");

        let json = serde_json::json!({
            "amount": amount.to_string(),
            "excess": excess_hex,
            "recipient_address": recipient_address.clone(),
            "recipient_sig": recipient_sig,
            "sender_address": grin_address_from_pubkey(&sender_pub, "grin"),
            "sender_sig": sender_sig,
        });
        (json, recipient_address)
    }

    #[test]
    fn grin_address_round_trips() {
        let (_, pk) = keypair();
        let grin = grin_address_from_pubkey(&pk, "grin");
        assert!(grin.starts_with("grin1"));
        assert_eq!(decode_grin_address(&grin), Some(pk));
    }

    #[test]
    fn message_layout_is_amount_excess_sender() {
        let (_, sender) = keypair();
        let excess_hex = hex::encode([7u8; 33]);
        let msg = payment_proof_message(5, &excess_hex, &sender).unwrap();
        assert_eq!(msg.len(), 73);
        assert_eq!(&msg[0..8], &[0, 0, 0, 0, 0, 0, 0, 5]);
        assert_eq!(&msg[41..], &sender);
    }

    #[test]
    fn message_rejects_wrong_length_excess() {
        let (_, sender) = keypair();
        assert!(payment_proof_message(5, &hex::encode([0u8; 10]), &sender).is_none());
    }

    #[test]
    fn parse_requires_all_six_fields() {
        let (good, _) = make_proof(1_500_000_000);
        assert!(parse_payment_proof(&good).is_some());
        // Drop sender_sig: no longer a full proof.
        let mut obj = good.as_object().unwrap().clone();
        obj.remove("sender_sig");
        assert!(parse_payment_proof(&Value::Object(obj)).is_none());
    }

    #[test]
    fn genuine_proof_verifies_both_signatures() {
        let (json, _) = make_proof(1_500_000_000);
        let proof = parse_payment_proof(&json).unwrap();
        assert!(verify_signatures(&proof));
    }

    #[test]
    fn tampered_recipient_signature_is_rejected() {
        let (json, _) = make_proof(1_500_000_000);
        let mut proof = parse_payment_proof(&json).unwrap();
        proof.recipient_sig_hex.replace_range(0..2, "ff");
        assert!(!verify_signatures(&proof));
    }

    #[test]
    fn tampered_sender_signature_is_rejected() {
        let (json, _) = make_proof(1_500_000_000);
        let mut proof = parse_payment_proof(&json).unwrap();
        proof.sender_sig_hex.replace_range(0..2, "ff");
        assert!(!verify_signatures(&proof));
    }

    #[test]
    fn wrong_amount_breaks_the_signature() {
        // The amount is bound into the signed message, so changing it (without
        // a fresh signature) fails verification.
        let (json, _) = make_proof(1_500_000_000);
        let mut proof = parse_payment_proof(&json).unwrap();
        proof.amount += 1;
        assert!(!verify_signatures(&proof));
    }
}
