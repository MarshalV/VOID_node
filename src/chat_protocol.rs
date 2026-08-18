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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct OnionHopHint {
    #[serde(default)]
    pub(crate) peer_id: String,
    #[serde(default)]
    pub(crate) pk_hex: String,
    #[serde(default)]
    pub(crate) addrs: Vec<String>,
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
        /// Other VOID nodes' onion X25519 keys (clients wrap 1/2/3 hops).
        #[serde(default)]
        onion_keys: Vec<OnionHopHint>,
    },
    /// Client→client NAT hint; bootstrap just Acks.
    DialBack {
        #[serde(default)]
        circuit_addrs: Vec<String>,
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
    PrekeyPut {
        peer_id: String,
        #[serde(default)]
        public_key: [u8; 32],
    },
    PrekeyGet {
        peer_id: String,
    },
    PrekeyOffer {
        peer_id: String,
        #[serde(default)]
        public_key: [u8; 32],
    },
    Encrypted {
        #[serde(default)]
        header: MessageHeader,
        #[serde(default)]
        ciphertext: Vec<u8>,
    },
    Onion {
        #[serde(default)]
        eph: [u8; 32],
        #[serde(default)]
        nonce: [u8; 12],
        #[serde(default)]
        ct: Vec<u8>,
    },
    OnionDrop {
        src: String,
        packet: Box<V1Packet>,
    },
    Ack,
}