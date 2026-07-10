//! Compatible with VOID messenger `/void/chat/1.0.0` relay subset.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OfflineEnvelope {
    pub(crate) v: u8,
    pub(crate) sender: String,
    pub(crate) sender_pk: [u8; 32],
    pub(crate) message_id: String,
    pub(crate) kind: String,
    pub(crate) eph: [u8; 32],
    pub(crate) nonce: [u8; 12],
    pub(crate) ct: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct MessageHeader {
    #[serde(default)]
    pub(crate) dh_pub: [u8; 32],
    #[serde(default)]
    pub(crate) pn: u32,
    #[serde(default)]
    pub(crate) n: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum V1Packet {
    Hello {
        #[serde(default)]
        public_key: [u8; 32],
        #[serde(default)]
        ephemeral_key: [u8; 32],
        #[serde(default)]
        transport_sig: Vec<u8>,
        #[serde(default)]
        transport_pubkey_pb: Vec<u8>,
    },
    BootstrapGossip {
        #[serde(default)]
        addrs: Vec<String>,
    },
    OfflineMailboxStore {
        recipient: String,
        envelopes: Vec<OfflineEnvelope>,
    },
    OfflineMailboxQuery {
        recipient: String,
    },
    OfflineMailboxDeliver {
        envelopes: Vec<OfflineEnvelope>,
    },
    Encrypted {
        #[serde(default)]
        header: MessageHeader,
        #[serde(default)]
        ciphertext: Vec<u8>,
    },
    Ack,
}