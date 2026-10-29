# VOID bootstrap / DNS-Seed node

Version 0.4 — no web UI. The node asks for a network entry point in the
terminal, then runs as:

1. **libp2p bootstrap / relay** (`/void/v1` + `/void/kad/1.0.0`) — TCP/UDP **4001** by default.
2. **Offline mail / prekey** — store-and-forward on `/void/chat/1.0.0` (`relay_mailbox.bin`). The frame is JSON or CBOR; the `ct` body is opaque either way. The file on disk is encrypted (see [Offline mail](#offline-mail) and [Chat wire](#chat-wire)).
3. **DNS-Seed server** — separate TCP port **4010**, hands other VOID nodes
   an encrypted list of known peers over `VOID-SEED/v1`.

Seed exchange between nodes is inside AEAD (Ed25519 + PFS). **Client** libp2p traffic (Identify, Circuit Relay, mailbox) is a different layer: chat content is E2EE, routing metadata the node **does see**. This is not anonymous routing and not Tor.

One such node is the normal mode for VOID (discovery, NAT, relay, mailbox). It does **not** hide the Alice ↔ Bob pair. An anonymous-routing layer is a separate plan, see below.

---

## Requirements

- [Rust](https://rustup.rs/) (stable)
- Public IPv4 (or DNS) and port forwarding on the router:
  - **TCP 4001** and **UDP 4001** — libp2p,
  - **TCP 4010** — seed exchange between nodes.

## Build

```bash
git clone https://github.com/MarshalV/bootstrap_node
cd bootstrap_node
cargo build --release
```

Binary: `target/release/void-bootstrap-node` (on Windows — `.exe`). On a small VPS, building `libp2p` is often killed by lack of RAM or disk: add swap (~2 GiB), use `cargo build --release -j 1`, and do not keep `target/debug` around at the same time.

## Run

```bash
./void-bootstrap-node
```

On start you get a prompt (English locale shown):

```
=== VOID bootstrap (seed + relay + DNS-Seed) ===
PeerId:       12D3KooW...
libp2p port:  4001 (env LISTEN_PORT)
seed  port:   4010 (env SEED_PORT)
known nodes:  0 (loaded from known_nodes.json)

Enter IP[:port] of another VOID node to join the network
  (Enter — isolated network; default port 4010):
```

Two modes.

### Isolated network

Just press **Enter**. The node starts its own listeners and can
serve VOID clients and accept inbound seed connections. It does not
dial anyone. This is the right mode for the **first** node in a network.

### Joining an existing network

Enter another VOID node / DNS-Seed address: `198.51.100.10` or `198.51.100.10:4010`,
or `seed.example.com:4010`. The node then:

1. opens a TCP connection,
2. runs the encrypted `VOID-SEED/v1` handshake,
3. checks that the far side is a VOID node
   (Ed25519 signature over the ephemeral keys, PeerId, and timestamp),
4. sends our known-peer list,
5. receives theirs,
6. immediately tries libp2p dials to every received peer and
   runs `kad.bootstrap()` to build the DHT.

The list is saved in `known_nodes.json` next to the binary, so later
starts reconnect without asking again.

The first run also creates `bootstrap_peer.key` — **keep it safe**,
it is your `PeerId` and the static Ed25519 key for the seed protocol.

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LISTEN_PORT` | `4001` | libp2p port (TCP + UDP/QUIC). |
| `SEED_PORT` | `4010` | Encrypted seed-protocol port. |
| `SEED_BIND` | `0.0.0.0:$SEED_PORT` | Seed server bind address. |
| `PUBLIC_HOST` | — | Public host/IP for clients (optional; CloudPub/UPnP may fill it in) |
| `PUBLIC_LIBP2P_PORT` | — | External libp2p TCP port if it differs from `LISTEN_PORT` |
| `PUBLIC_SEED_PORT` | — | External seed TCP port if it differs from `SEED_PORT` |
| `AUTO_PORT_FORWARD` | `0` | `1` — request UPnP mapping of `LISTEN_PORT` and `SEED_PORT` |
| `CLOUDPUB_CONFIG` | `~/.config/cloudpub/client.toml` | Path to CloudPub (`clo`) config |
| `CLOUDPUB_AUTO_PUBLISH` | `0` | `1` — `clo register tcp …` + `clo run` for libp2p and seed |
| `RUST_LOG` | `info` | tracing log level. |

## Protocol `/void-seed/v1` — on the wire

```
    Client (node A)                                Server (node B)
        |                                               |
        |  msg1 = e_c_pub (32 random-looking bytes)     |
        | --------------------------------------------> |
        |                                               |
        |  msg2 = e_s_pub || AEAD(k1, n=0, auth_s)      |
        | <-------------------------------------------- |
        |                                               |
        |  msg3 = AEAD(k2, n=0, auth_c || request)      |
        | --------------------------------------------> |
        |                                               |
        |  msg4 = AEAD(k2, n=1, peer_list)              |
        | <-------------------------------------------- |
```

- Key exchange: ephemeral **X25519** (PFS, keys discarded after the session).
- Key derivation: `HKDF-SHA-512` with `salt = "VOID-SEED/v1" || e_c || e_s` →
  64 bytes, first 32 are `k1`, next 32 are `k2`. All later messages
  are `ChaCha20-Poly1305` (AEAD, 96-bit nonce = counter, `aad="VOID-SEED/v1"`).
- Authentication: the static `Ed25519` key (same as the libp2p `PeerId`)
  on both sides signs `"VOID-SEED/v1|<dir>|e_c||e_s||own PeerId||timestamp"`;
  the client also appends the server PeerId. Timestamp is checked with a ±5 min window.
  `protocol_version = "/void/v1"` inside AEAD is a version marker, not access
  control: any running instance of this program can produce it. An old node
  will not complete handshake with this signature.
- A passive observer sees only 32 “random” bytes and then
  an encrypted stream. Neither PeerId, nor the node list, nor the
  `/void/v1` marker appears in the clear.

## Connecting a regular VOID client

Unchanged — for VOID clients this node is still a valid libp2p seed.
Line for `void-bootstrap.txt`:

```
/ip4/<YOUR_PUBLIC_IP>/tcp/4001/p2p/<PEER_ID>
```

## Running in the background (Windows)

NSSM:

- path to `target\release\void-bootstrap-node.exe`,
- working directory — the folder with the binary, `bootstrap_peer.key`, and `known_nodes.json`,
- set `PUBLIC_HOST` in the NSSM panel so the node can advertise itself.

The terminal prompt does not work under NSSM — run once by hand,
press `Enter` (isolated network) or type the address, then register
the service without that step, relying on saved `known_nodes.json`.
In service mode the node skips the interactive step (closed stdin
returns an empty line → isolated mode, and it restores connections from
`known_nodes.json`).

## What the operator of this node sees

Client chat is **not** forwarded as plaintext (live-session `V1Packet::Encrypted` is ignored). Circuit Relay forwards opaque bytes. The node is still on the path, not a hole in the wall.

```
Alice
  │  E2EE
  ▼
this node (Relay / Bootstrap)
  │
  ▼
Bob
```

At `RUST_LOG=info` (the default) and in process state the node can correlate:

| Observation | Source |
|-------------|--------|
| Client IP + PeerId | `ConnectionEstablished` (`endpoint`) |
| Alice ↔ Bob | `relay: circuit accepted` (`src` / `dst`) |
| time and volume | connection duration, relay bytes |
| offline “to whom, when, how much” | in-memory `OfflineMailboxStore` / `Query`: uploader and recipient PeerId, size. Client v3 envelopes have no sender or type; old clients (v2) leave `sender` / `kind` in the clear |

E2EE protects content. One node does **not** give routing anonymity: `Alice → Node A → Bob` lets Node A link sender and recipient.

Several copies of this program under **one** operator are ≈ one node for trust. What matters is independence of operators, not process count.

## Offline mail

`OfflineMailboxStore` puts an envelope in the recipient’s box, `OfflineMailboxQuery` returns a batch and deletes it.

| Rule | Value |
|------|-------|
| Who can fetch mail | only the recipient: `recipient` in `Query` must match the connection PeerId (Noise already proved key ownership). A foreign query gets an empty reply, the box is untouched |
| Envelope lifetime | 7 days from accept, then deleted (checked on accept, on deliver, and every 90 s) |
| Recipient box | up to 1024 envelopes and 32 MiB |
| One uploader in one box | up to 256 envelopes and 8 MiB. Uploader is the connection PeerId; on disk only its keyed hash is stored |
| Box overflow | the oldest envelope of the heaviest uploader is evicted — flood pushes itself out, not other people’s mail |
| Mailbox ceiling | at most 4096 boxes. A new recipient past that is refused; an existing box still accepts mail |
| `Store` rate | per peer per minute: 600 requests, 600 envelopes, 48 MiB |
| One `Store` | at most 64 envelopes; each `ct` at most 256 KiB. A larger field is rejected before it is stored. One `Deliver` is at most 1024 envelopes with the same `ct` cap |
| Refusal | empty `OfflineMailboxDeliver` instead of `Ack`; the client does not treat the letter as handed off and retries later |
| Prekey | `PrekeyPut` is stored only when the Noise peer is the claimed owner, the signature matches the identity key in that PeerId, and `not_after` is in the future and at most 30 days out. An unsigned or expired put is refused. `PrekeyGet` returns `PrekeyOffer` with `public_key`, `not_after`, and `sig` while the record is unexpired |

`relay_mailbox.bin` is encrypted with ChaCha20-Poly1305, key from `bootstrap_peer.key` (HKDF, `VOID_MAILBOX_v1`); box names are PeerId hashes with the same key. An operator who has `bootstrap_peer.key` can decrypt the file; someone who stole only the file cannot. The old file format (no lifetime) is still readable; lifetime starts at the first run of this version. Clients seal new mail to this prekey. The key derived from the recipient PeerId is only the fallback when no sealable prekey is published.

Kademlia `put` on this node keeps two kinds of record and drops the rest: `/void/prekey/<PeerId>` with the owner’s signature and an expiry of at most 30 days, and `/void/mailbox/<PeerId>` as a bincode list of v3 envelopes. Provider records (`start_providing`) are unchanged.

## Chat wire

`/void/chat/1.0.0` carries the same `V1Packet` as the client (Hello, mailbox, prekey, onion, `Ack`). Request body at most 4 MiB, response at most 16 MiB.

The node reads JSON and CBOR on every frame:

1. content-type `VC\x01\x01` then JSON, or `VC\x01\x02` then CBOR;
2. else CBOR magic `d9 d9 f7`, then the CBOR value;
3. else the first byte: `{`, `[`, `"`, or whitespace is JSON, anything else is CBOR.

`Vec<u8>` (`ct`, `ciphertext`, signatures) is a CBOR byte string. Fixed arrays `[u8; N]` stay arrays of numbers, so a JSON client and the bincode mailbox file still match. A reply uses the encoding of the request.

This process does not send Hello. It announces `HELLO_CAP_CBOR` as `;cbor=1` at the end of the Identify agent string. A current client switches later requests to CBOR after it sees that tag. A client or node without the announcement keeps receiving JSON. Outbound frames this node starts (onion directory, a forwarded cell) are CBOR only when that next peer announced the capability, in its agent tag or in a Hello with bit `2`.

## Onion hop (`VOID_ONION_v1` and `v2`)

VOID clients wrap live chat (Hello / small Encrypted / Ack) in onion cells. This node peels **one** layer and forwards `next` — another bootstrap or the recipient. It does not read the mail. The inner frame is sent only after that hop’s Identify has completed; a connection that is merely established stays queued. `next` must parse as a PeerId and must not be this node. Forwarding is limited to 600 cells per minute from the previous hop and 6000 per minute overall. Logs do not record `next` or `src`.

v1 is the JSON cell. The inner packet is re-serialized: `Hello.caps`, `ts`, and `nonce` are **kept**. New clients sign those three fields; stripping `caps` makes the onion Hello fail. A v1 exit still receives `OnionDrop.src`.

v2 is a fixed cell of 2, 16, or 64 KiB (`Onion2`). This node decrypts slot 0, XORs the body, and either forwards the same-length cell or, on the exit, sends `OnionDeliver` with the opaque body. It does not learn the sender. Both the current secret and the previous one are tried, so a cell sent just before rotation still opens.

```
1 node:   Alice → this node → Bob
2+ nodes: Alice → A → B → [C] → Bob
```

The key is advertised in Identify: `void-bootstrap-node/0.4;onion=<64 hex>;osig=<hex>;epoch=<u64>;until=<unix>;op=<label>;osig2=<hex>;cbor=1`. `op` is `VOID_OPERATOR` (up to 32 bytes, no `;`). `;cbor=1` is always present on this build; older clients ignore the tag and keep sending JSON. The outer chat frame to the next hop is CBOR only if that hop announced the same capability. The v1 cell payload inside the seal stays JSON. The public key rotates every 7 days. `onion.key` stores the current secret and the previous one; the previous secret is deleted one day after its `not_after`. A 32-byte `onion.key` from an older build is kept as epoch 1 and given a 7-day expiry, so the advertised key does not jump on the first start. Identify’s agent string is fixed until restart; after a rotation the new descriptor is pushed in `BootstrapGossip`. File `onion.key` next to the binary — do not publish.

One node still links the two ends: it sees Alice’s IP and Bob’s PeerId. Several **independent** operators are needed before entry and exit are different people. Several copies under one person ≈ one node. Set `VOID_OPERATOR` to a stable label so clients can avoid putting two of your nodes on one path.

Circuit Relay v2 and mailbox work as before (NAT, offline mail).

## Security

- `bootstrap_peer.key` — static key. A leak lets someone impersonate
  your node in seed exchange. Keep backups and keep it secret.
- `known_nodes.json` — public addresses. Not critical; add to `.gitignore`
  if you want.
- `relay_mailbox.bin` — offline mail, encrypted with a key from `bootstrap_peer.key`. Together with the key it shows how many letters wait in each box. Do not publish or share.
- `onion.key` — hop key for `VOID_ONION_v1` and `v2`. A leak peels this node’s layer until the secret is erased (current key: 7 days, previous key: one day after that).

## License

MIT — see [LICENSE](LICENSE).
