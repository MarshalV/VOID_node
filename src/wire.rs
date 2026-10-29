//! JSON и CBOR одного `V1Packet` на `/void/chat/1.0.0`.
//!
//! Те же байты, что у клиента: content-type `VC\x01\x02`, магия `d9 d9 f7`,
//! иначе первый байт. `Vec<u8>` в CBOR — байтовая строка.

use anyhow::{anyhow, Result};

use crate::chat_protocol::V1Packet;

pub const HELLO_CAP_CBOR: u32 = 2;
pub const MAX_CT_BYTES: usize = crate::onion::MAX_CT_BYTES;
pub const MAX_CIPHERTEXT_BYTES: usize = 1024 * 1024;
pub const MAX_STORE_ENVELOPES: usize = 64;
pub const MAX_DELIVER_ENVELOPES: usize = 1024;
pub const REQUEST_MAX_BYTES: u64 = 4 * 1024 * 1024;
pub const RESPONSE_MAX_BYTES: u64 = 16 * 1024 * 1024;

const CONTENT_TYPE_CBOR: [u8; 4] = [b'V', b'C', 0x01, 0x02];
const CBOR_MAGIC: [u8; 3] = [0xd9, 0xd9, 0xf7];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireEncoding {
    Json,
    Cbor,
}

pub fn encode_v1_packet(packet: &V1Packet, encoding: WireEncoding) -> Result<Vec<u8>> {
    check_v1_limits(packet)?;
    match encoding {
        WireEncoding::Json => serde_json::to_vec(packet).map_err(|e| anyhow!("json encode: {e}")),
        WireEncoding::Cbor => {
            let mut out = Vec::with_capacity(CONTENT_TYPE_CBOR.len() + 64);
            out.extend_from_slice(&CONTENT_TYPE_CBOR);
            out.extend(cbor_bytes(packet)?);
            Ok(out)
        }
    }
}

pub fn decode_v1_packet(bytes: &[u8]) -> Result<(V1Packet, WireEncoding)> {
    let (packet, encoding) = sniff_decode(bytes)?;
    check_v1_limits(&packet)?;
    Ok((packet, encoding))
}

fn sniff_decode(bytes: &[u8]) -> Result<(V1Packet, WireEncoding)> {
    if bytes.len() >= 4 && bytes[0] == b'V' && bytes[1] == b'C' && bytes[2] == 0x01 {
        return match bytes[3] {
            0x01 => decode_json(&bytes[4..]).map(|p| (p, WireEncoding::Json)),
            0x02 => decode_cbor(&bytes[4..]).map(|p| (p, WireEncoding::Cbor)),
            other => Err(anyhow!("unknown content-type {other}")),
        };
    }
    if bytes.len() >= 3 && bytes[..3] == CBOR_MAGIC {
        return decode_cbor(&bytes[3..]).map(|p| (p, WireEncoding::Cbor));
    }
    match bytes.first().copied() {
        Some(b'{') | Some(b'[') | Some(b'"') | Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r') => {
            decode_json(bytes).map(|p| (p, WireEncoding::Json))
        }
        Some(_) => decode_cbor(bytes).map(|p| (p, WireEncoding::Cbor)),
        None => Err(anyhow!("empty chat frame")),
    }
}

fn decode_json(bytes: &[u8]) -> Result<V1Packet> {
    serde_json::from_slice(bytes).map_err(|e| anyhow!("json decode: {e}"))
}

fn decode_cbor(bytes: &[u8]) -> Result<V1Packet> {
    cbor4ii::serde::from_slice(bytes).map_err(|e| anyhow!("cbor decode: {e:?}"))
}

fn cbor_bytes(packet: &V1Packet) -> Result<Vec<u8>> {
    cbor4ii::serde::to_vec(Vec::new(), packet).map_err(|e| anyhow!("cbor encode: {e:?}"))
}

pub fn check_v1_limits(packet: &V1Packet) -> Result<()> {
    match packet {
        V1Packet::Encrypted { ciphertext, .. } => {
            if ciphertext.len() > MAX_CIPHERTEXT_BYTES {
                return Err(anyhow!(
                    "ciphertext {} exceeds {}",
                    ciphertext.len(),
                    MAX_CIPHERTEXT_BYTES
                ));
            }
        }
        V1Packet::Onion { ct, .. } => {
            if ct.len() > MAX_CT_BYTES {
                return Err(anyhow!("ct {} exceeds {}", ct.len(), MAX_CT_BYTES));
            }
        }
        V1Packet::OfflineMailboxStore { envelopes, .. } => {
            check_envelopes(envelopes.len(), envelopes.iter().map(|e| e.ct.len()), MAX_STORE_ENVELOPES)?;
        }
        V1Packet::OfflineMailboxDeliver { envelopes } => {
            check_envelopes(
                envelopes.len(),
                envelopes.iter().map(|e| e.ct.len()),
                MAX_DELIVER_ENVELOPES,
            )?;
        }
        V1Packet::OnionDrop { packet, .. } => check_v1_limits(packet)?,
        _ => {}
    }
    Ok(())
}

fn check_envelopes(
    count: usize,
    ct_lens: impl Iterator<Item = usize>,
    max_count: usize,
) -> Result<()> {
    if count > max_count {
        return Err(anyhow!("envelopes {count} exceeds {max_count}"));
    }
    for n in ct_lens {
        if n > MAX_CT_BYTES {
            return Err(anyhow!("envelope ct {n} exceeds {MAX_CT_BYTES}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_ack_and_cbor_roundtrip() {
        let json = encode_v1_packet(&V1Packet::Ack, WireEncoding::Json).unwrap();
        assert_eq!(json, b"\"Ack\"");
        let (pkt, enc) = decode_v1_packet(&json).unwrap();
        assert!(matches!(pkt, V1Packet::Ack));
        assert_eq!(enc, WireEncoding::Json);

        let cbor = encode_v1_packet(&V1Packet::Ack, WireEncoding::Cbor).unwrap();
        assert!(cbor.starts_with(&CONTENT_TYPE_CBOR));
        let (pkt, enc) = decode_v1_packet(&cbor).unwrap();
        assert!(matches!(pkt, V1Packet::Ack));
        assert_eq!(enc, WireEncoding::Cbor);
    }

    #[test]
    fn legacy_json_and_raw_cbor_and_magic() {
        let packet = V1Packet::Encrypted {
            header: Default::default(),
            ciphertext: vec![7u8; 40],
        };
        let json = serde_json::to_vec(&packet).unwrap();
        assert_eq!(json[0], b'{');
        let (_, enc) = decode_v1_packet(&json).unwrap();
        assert_eq!(enc, WireEncoding::Json);

        let raw = cbor_bytes(&packet).unwrap();
        let (_, enc) = decode_v1_packet(&raw).unwrap();
        assert_eq!(enc, WireEncoding::Cbor);

        let mut magic = CBOR_MAGIC.to_vec();
        magic.extend_from_slice(&raw);
        let (_, enc) = decode_v1_packet(&magic).unwrap();
        assert_eq!(enc, WireEncoding::Cbor);
        assert!(encode_v1_packet(&packet, WireEncoding::Cbor).unwrap().len() < json.len());
    }

    #[test]
    fn store_count_and_ct_limits() {
        let env = crate::chat_protocol::OfflineEnvelope {
            v: 3,
            sender: String::new(),
            sender_pk: [0u8; 32],
            message_id: "a".into(),
            kind: String::new(),
            eph: [1u8; 32],
            nonce: [2u8; 12],
            ct: vec![3u8; 4],
        };
        let mut many = Vec::new();
        many.resize(MAX_STORE_ENVELOPES + 1, env);
        assert!(check_v1_limits(&V1Packet::OfflineMailboxStore {
            recipient: "p".into(),
            envelopes: many,
        })
        .is_err());
        assert!(check_v1_limits(&V1Packet::Onion {
            eph: [0u8; 32],
            nonce: [0u8; 12],
            ct: vec![1u8; MAX_CT_BYTES + 1],
        })
        .is_err());
    }

    #[test]
    fn bincode_ct_layout_unchanged() {
        #[derive(serde::Serialize)]
        struct Plain {
            ct: Vec<u8>,
        }
        #[derive(serde::Serialize)]
        struct Bytes {
            #[serde(with = "serde_bytes")]
            ct: Vec<u8>,
        }
        let ct = vec![1u8, 2, 255];
        assert_eq!(
            bincode::serialize(&Plain { ct: ct.clone() }).unwrap(),
            bincode::serialize(&Bytes { ct }).unwrap()
        );
    }
}
