# VOID bootstrap / DNS-Seed node

Version 0.4 — no web UI. The node asks for a network entry point in the
terminal, then runs as:

1. **libp2p bootstrap / relay** (`/void/v1` + `/void/kad/1.0.0`) — TCP/UDP **4001** by default.
2. **Offline mail / prekey** — store-and-forward on `/void/chat/1.0.0` (`relay_mailbox.bin`). The `ct` body is opaque. The file on disk is encrypted (see [Offline mail](#offline-mail)).
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
| `Store` rate | per peer per minute: 600 requests, 600 envelopes, 48 MiB |
| Refusal | empty `OfflineMailboxDeliver` instead of `Ack`; the client does not treat the letter as handed off and retries later |

`relay_mailbox.bin` is encrypted with ChaCha20-Poly1305, key from `bootstrap_peer.key` (HKDF, `VOID_MAILBOX_v1`); box names are PeerId hashes with the same key. An operator who has `bootstrap_peer.key` can decrypt the file; someone who stole only the file cannot. The old file format (no lifetime) is still readable; lifetime starts at the first run of this version. Clients do not use prekeys on this node for sealing: the offline-mail key is derived from the recipient PeerId.

## Anonymous routing layer (`VOID_ONION_v1`)

VOID clients wrap live chat (Hello / Encrypted) in onion cells. This node peels **one** layer with its `onion.key` and forwards `next` — another bootstrap or the recipient. The inner packet is re-serialized: `Hello.caps`, `ts`, and `nonce` are **kept**. Without them a new client will reject `Hello` (v2 signature fails), and a session without `caps` stays without header AAD.

```
1 node:   Alice → this node → Bob
2+ nodes: Alice → A → B → [C] → Bob
```

The key is advertised in Identify: `void-bootstrap-node/0.4;onion=<64 hex>`. File `onion.key` next to the binary — do not publish.

One node still correlates Alice↔Bob after unwrap. Several **independent** operators are needed so entry does not know Bob and exit does not know Alice’s IP. Several copies under one person ≈ one node.

Circuit Relay v2 and mailbox work as before (NAT, offline mail).

## Security

- `bootstrap_peer.key` — static key. A leak lets someone impersonate
  your node in seed exchange. Keep backups and keep it secret.
- `known_nodes.json` — public addresses. Not critical; add to `.gitignore`
  if you want.
- `relay_mailbox.bin` — offline mail, encrypted with a key from `bootstrap_peer.key`. Together with the key it shows how many letters wait in each box. Do not publish or share.
- `onion.key` — VOID_ONION_v1 hop key. A leak lets someone peel this node’s layer.

## License

MIT — see [LICENSE](LICENSE).
