# Notabene Travel Rule — end-to-end encrypted PII (Java / Spring Boot)

A Spring Boot port of the JavaScript project, where **you** own the encryption:

- **vaspA** encrypts IVMS101 PII with its own code and posts only ciphertext to Notabene.
- **vaspB** pulls the transfer with `include_ivms=true` and decrypts locally with a private key that never leaves it.
- Notabene never sees plaintext.

Java 17, Spring Boot 4.0.4, Jackson 3. The crypto is plain JCA — no BouncyCastle, no Nimbus.

## Quick start

```bash
export JAVA_HOME=$(/usr/libexec/java_home -v 17)
./mvnw spring-boot:run   # or: mvn spring-boot:run
```

Then, with no credentials and no network:

```bash
curl -s localhost:8080/api/demo | jq
```

```
field                                              sent                 received
= originator.orig.primaryIdentifier                Doe                  Doe
= originator.orig.dateAndPlaceOfBirth.dateOfBirth  1980-01-01           1980-01-01
...
piiMatches: true | mismatches: 0
```

## The REST API

| Method | Path | What it does |
|---|---|---|
| `GET` | `/api/demo?mode=branch\|field` | Offline round trip: encrypt → "store" → decrypt → compare. No credentials. |
| `POST` | `/api/send` | Send a Travel Rule message from one VASP to another. |
| `POST` | `/api/startPool` | Start polling Notabene for incoming messages for a VASP and decrypt them. |
| `POST` | `/api/stopPool` | Stop that poller. |
| `GET` | `/api/pollStatus` | Which pollers run, and the PII they have decrypted. |
| `GET` | `/api/vasps` | Configured VASPs, their public PII keys, and DIDDoc entries to publish. |
| `GET` | `/api/transfers` | Transfers for one VASP or all of them, newest first. |
| `GET` | `/api/transfers/{id}?vasp=` | One transfer: stored ciphertext next to what that VASP decrypts. |
| `GET` | `/api/samplePii` | The editable IVMS101 template. |
| `GET` | `/api/register/initiate` | Step 1 of registering an address: the exact message to sign. |
| `POST` | `/api/register/complete` | Step 2: register the address to one of your VASPs, with the signed proof. |
| `GET` | `/api/registration-status` | Is an address registered, and to whom? |

`pollStatus` and `vasps` are additions — you asked for four endpoints, but polling is only useful if
you can read what it found, and `vasps` is what makes the setup guide below actionable.

### demo

```bash
curl -s "localhost:8080/api/demo?mode=branch" | jq '{mode, piiMatches, mismatches, otherMode}'
```

Returns the plaintext PII, each JWE produced, the exact body that would go to Notabene, the error a
third party gets when it tries to decrypt with its own key, the decrypted result, and a field-by-field
comparison. The same thing is written to the application log.

### send

```bash
curl -s -X POST localhost:8080/api/send \
  -H 'Content-Type: application/json' \
  -d '{"from":"vaspA","beneficiaryAddress":"0x56F5…","network":"ethereum"}' | jq
```

| Field | Required | Meaning |
|---|---|---|
| `from` | yes | configured VASP name that originates, e.g. `vaspA` |
| `beneficiaryAddress` | yes | settlement address, bare or CAIP-10. Notabene is asked who owns it; that VASP is the beneficiary. There is no `to` field. |
| `network` | yes | chain of that address: `ethereum`, `polygon`, … or a CAIP-2 id. An address naming a different chain is rejected. |
| `mode` | no | `branch` (default). `field` works on the local channel only; Notabene v2.1 takes one JWE per party. |
| `transferId` | no | present PII on an existing transfer instead of creating one |
| `originatorId` | no | IRI of the sending customer; defaults to the VASP's own customer (`urn:uuid:…`) |
| `pii` | no | your own IVMS101 object; defaults to `sample-pii.json` |

It looks up the address's owner in Notabene (the owner must have registered it — see
`register/complete`), fetches that VASP's published key, creates the transfer (`POST /api/v1/transfers`), encrypts locally, and POSTs one JWE per party to `/transfers/{id}/parties/{role}/encrypted-pii`.

### transfers

```bash
curl -s "localhost:8080/api/transfers?channel=local" | jq                  # every VASP
curl -s "localhost:8080/api/transfers?vasp=vaspB&channel=notabene" | jq    # one of them
curl -s "localhost:8080/api/transfers/<id>?vasp=vaspB&channel=local" | jq
```

`?channel=` selects where to read from — see the channel note below. The detail call fetches with
`include_ivms=true` and decrypts locally, returning the ciphertext, the plaintext, the JWE header and a
flat field list.

### register (initiate / complete) / registration-status

```bash
curl -s "localhost:8080/api/registration-status?vasp=vaspB&address=0x56F5…&network=ethereum" | jq

curl -s "localhost:8080/api/register/initiate?vasp=vaspB&address=0x56F5…&network=ethereum" | jq   # step 1
# sign the returned message, then:
curl -s -X POST localhost:8080/api/register/complete ...                                          # step 2
```

Registration is always two steps and always carries a signed proof — see below.

`network` takes a friendly name — `ethereum`, `sepolia`, `holesky`, `polygon`, `bitcoin` — or any
CAIP-2 id such as `eip155:42161`. The address may be bare or already CAIP-10; if it names a chain
that contradicts `network`, the call is rejected rather than silently reinterpreted. That matters:
the same hex on two chains is two different registrations.

Registration follows Notabene v2.1: `POST /api/v1/wallets` registers the address under the VASP's
customer, then `POST /api/v1/customers/{customer}/wallets/{address}/proofs` submits the proof. The
customer is `notabene.vasps.<name>.customer-id`, or a stable `urn:uuid:` derived from the DID and
created with `POST /api/v1/customers` on first use.

Missing or blank `address`, an empty account after a chain prefix, and bean-validation failures on
request bodies all return `400 bad_request` naming the offending field.

`registration-status` answers `{"registered": false, …}` when nobody owns it, and otherwise names
the owning VASP, its jurisdiction, and — when the owner is one of yours — its configured name.
Lookup is `POST /api/v1/wallet-ownerships/discover`; `source` says how Notabene knows (e.g.
`AddressHash`, meaning the owner registered it).

> **Testnets are unverified.** The v2.0 API rejected testnet chains (it priced every asset). The v2.1
> docs do not say either way; if a testnet address is refused, use a mainnet-shaped address and never settle it.

#### Proving ownership

A proof says the customer controls the address. `register/complete` requires one and submits it to
Notabene, which verifies signature types on submission (`Submitted` → `Accepted` or `Failed`).
`self-declaration` and `screenshot` proofs stay `Submitted` until Notabene compliance decides.

> **Documented vs. verified.** The v2.1 docs name the proof types and fields but do not say which
> fields each type needs, and do not mandate any attestation wording — the message from
> `register/initiate` copies an example from the v2.0 guide, so that Notabene accepts it is unconfirmed.
> The docs also say a proof is for a *self-hosted* wallet, which Notabene does not publish to
> counterparties, so `managed` defaults to `false` and other VASPs may not discover the address through
> this route. Register one in the sandbox and read the real `status` before relying on any of it.

```bash
# 1. get the exact message to sign (it carries a timestamp - sign it verbatim, don't rebuild it)
curl -s "localhost:8080/api/register/initiate?vasp=vaspB&address=0x56F5…&network=ethereum" | jq

# 2. sign it with the address's private key (see tools/ below)
# 3. register with the proof
curl -s -X POST localhost:8080/api/register/complete -H 'Content-Type: application/json' -d '{
  "vasp":"vaspB","address":"0x56F5…","network":"ethereum",
  "proof":{"type":"eip-191","attestation":"I certify that\n\n…","signature":"0x…"}}' | jq
```

| `proof` field | Required | Meaning |
|---|---|---|
| `type` | **yes** | `eip-191`, `bip-322`, `bip-137-xpub`, `self-declaration`, `screenshot` |
| `signature` | signature types | hex or base64 signature over the attestation |
| `attestation` | non-signature types (and the signed message for signature types) | text, or a URL for a screenshot |
| `walletProvider` | no | e.g. `MetaMask` |
| `xpub` | `bip-137-xpub` only | extended public key |
| `chainData` | no | extra chain-specific fields |

Also at the top level: `managed` (default `false`). This server does **not** verify the signature —
Notabene does. A 409 means another of your customers already holds a proof of that address.

`tools/sign-attestation.mjs` signs EIP-191 messages for testing (the JVM can't: keccak-256 and
secp256k1 would need BouncyCastle, and signing belongs with whoever custodies the key anyway):

```bash
cd tools && npm install
node sign-attestation.mjs --new                                  # throwaway key + its address
node sign-attestation.mjs --key 0x<privkey> --message "I certify that…"
```

It prints the address, and the `attestation` and `signature` to paste into `proof`.

### The local channel

`POST /api/send` and `GET /api/transfers` both take `channel`: `notabene` (default) or `local`.

`local` is an in-memory ledger on this server — identical encryption, no network. It exists because
Notabene will not hand out a counterparty key, or accept a presentation, until your `#pii` key is
published in the DID document, which for sandbox entities requires their support to publish. Until
then a live send fails with `404 NO_ENCRYPTION_KEYS`. The local channel lets you exercise the whole
encrypt → store → decrypt path in the meantime; listing live transfers works either way.

```bash
curl -s -X POST localhost:8080/api/send -H 'Content-Type: application/json' \
  -d '{"from":"vaspA","beneficiaryAddress":"0x56F5…","network":"ethereum","channel":"local"}' | jq

# the owner is still discovered from Notabene, and must be a VASP configured on this server
```

### startPool / stopPool

```bash
curl -s -X POST localhost:8080/api/startPool \
  -H 'Content-Type: application/json' \
  -d '{"vasp":"vaspB","intervalSeconds":15}' | jq

curl -s localhost:8080/api/pollStatus | jq
curl -s -X POST localhost:8080/api/stopPool -H 'Content-Type: application/json' -d '{"vasp":"vaspB"}'
```

The poller lists incoming transfers, fetches each new one with `include_ivms=true`, decrypts it with that
VASP's private key, and logs every field. A failing poll is recorded in `lastError` and the loop keeps
going, so a missing credential does not kill it.

Notabene also pushes `tap.requirePresentationSatisfied` webhooks, which is the better production
answer. Polling is here because it needs no public URL.

## Setting up test VASPs in Notabene

This is the part that is not code. Notabene's sandbox is not self-service end to end.

**1. Get a sandbox account.** Ask Notabene (support@notabene.id, or your solutions contact) for
sandbox access. You cannot create a sandbox tenant yourself. Ask for **two** entities so you have
both sides of a transfer — that is what `vaspA` and `vaspB` mean here.

**2. Note each entity's DID.** Sandbox entities get a Notabene-hosted `did:web`, shaped like
`did:web:notabeneid-63083.sandbox.notabene.id:tj` — the last segment is the jurisdiction. You will
find it in the Dashboard, and the DIDDoc is served at:

```
https://api.eu1.notabene.id/entity/<entityDID>/diddoc
```

For sandbox entities Notabene publishes the DIDDoc for you; the self-hosting steps in their
[DIDdoc setup](https://devx.notabene.id/docs/diddoc-setup) page do not apply.

**3. Get API credentials.** Dashboard → Settings → API credentials → create. The secret is shown
once. Do this for **both** entities: each VASP authenticates as itself.

**4. Put all of that in configuration.**

```bash
export VASP_A_DID=did:web:notabeneid-63083.sandbox.notabene.id:tj
export VASP_A_CLIENT_ID=...
export VASP_A_CLIENT_SECRET=...
export VASP_B_DID=did:web:notabeneid-63084.sandbox.notabene.id:no
export VASP_B_CLIENT_ID=...
export VASP_B_CLIENT_SECRET=...
```

**5. Generate your PII keys and publish them.**

```bash
curl -s localhost:8080/api/vasps | jq
```

Keys are generated on first use into `keys/<vasp>.json` and reused afterwards. The response gives you
a `didDocEntry` per VASP:

```json
{
  "id": "did:web:...#pii",
  "type": "JsonWebKey2020",
  "controller": "did:web:...",
  "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
}
```

Notabene pre-populates your DIDDoc with a `#notabene-pii` entry holding **their** key — that is
managed encryption, and it is why they can read your PII by default. To go self-managed, replace that
entry with yours (or add `#pii`, which their key resolution prefers), add the id to `keyAgreement`,
and make sure `@context` includes `https://w3id.org/security/suites/ecdsa-2019/v1`.

> **This is the step with no API.** For sandbox entities, Notabene's own recipe says to *"reach out to
> support to publish the updated docs"*. Send them the updated DIDDoc and wait. There is no
> self-service upload endpoint — do not go looking for one.
>
> `didDocEntryHexVariant` in the same response is the older
> `EcdsaSecp256r1VerificationKey2019` + `publicKeyHex` encoding from their
> [Key Management in DIDdocs](https://devx.notabene.id/docs/key-management-in-diddocs) page. Send
> whichever form support asks for.

**6. Turn off Notabene-managed encryption** in Dashboard → Settings. Without this the platform keeps
encrypting to its own key and the exchange is not end-to-end.

**7. Wait ~5 minutes.** DIDDoc resolution is cached with a 5 minute TTL.

**8. Check it took.**

```bash
curl -s -X POST localhost:8080/api/send -H 'Content-Type: application/json' \
  -d '{"from":"vaspA","beneficiaryAddress":"0x56F5…","network":"ethereum"}' | jq '{transferId, recipientKid, warning}'
```

If `recipientKid` does not end in `#pii` or `#notabene-pii`, or `warning` is set, your key is not
live yet and the PII would be encrypted to a Notabene-held key.

**9. Receive it.**

```bash
curl -s -X POST localhost:8080/api/startPool -H 'Content-Type: application/json' -d '{"vasp":"vaspB"}'
curl -s localhost:8080/api/pollStatus | jq '.[0].recent'
```

## How much goes into each JWE

`notabene.pii-mode`, or `?mode=` / `"mode"` per request.

**`branch`** (default) — one JWE for `ivms101.originator`, one for `ivms101.beneficiary`:

```json
POST /api/v1/transfers/{id}/parties/originator/encrypted-pii   { "ivms_encrypted": "eyJhbGciOiJFQ0RILUVTIiwi..." }
POST /api/v1/transfers/{id}/parties/beneficiary/encrypted-pii  { "ivms_encrypted": "eyJhbGciOiJFQ0RILUVTIiwi..." }
```

Two JWEs instead of fifteen, and the structure leaks nothing.

**`field`** — every leaf value becomes its own JWE, the IVMS101 tree stays visible. Notabene v2.1 takes a
single JWE per party, so this mode is for the offline demo and the local channel only; `send` on the
notabene channel refuses it.

Decryption auto-detects, so a receiving VASP never needs to be told which mode the sender used.

## How the encryption works

Implemented in [`EcdhEsJwe`](src/main/java/id/notabene/e2ee/crypto/EcdhEsJwe.java) on plain JCA,
following Notabene's [encryption](https://devx.notabene.id/docs/encryption-workflow-1) and
[decryption](https://devx.notabene.id/docs/decryption-workflow-1) workflows and their
[interop profile](https://gitlab.com/notabene/open-source/notabene-encryption-examples):

| | |
|---|---|
| Key agreement | ECDH on P-256, fresh ephemeral sender key per JWE (`alg: ECDH-ES`) |
| Key derivation | ConcatKDF (RFC 7518 §4.6.2) → 256-bit CEK |
| Content encryption | AES-256-GCM (`enc: A256GCM`), protected header as AAD |
| Binding | `apu = SHA-256(sender DID)`, `apv = SHA-256(recipient key id)`, both verified on decrypt |
| Plaintext | **JSON-serialised** before encryption — `"Doe"` with quotes, not `Doe` |
| Serialization | JWE compact, empty encrypted-key segment: `header..iv.ciphertext.tag` |

The JSON serialisation is not cosmetic: Notabene's reference implementation marks it
*"CRITICAL: JSON.stringify the value for Notabene compatibility"*. It is also what lets a whole
`originator` object be encrypted as one value.

Ephemeral public keys from a JWE header are checked to be on the P-256 curve before use, as their
decryption workflow requires.

## Interoperability with the JavaScript project

[`JavaScriptInteropTest`](src/test/java/id/notabene/e2ee/JavaScriptInteropTest.java) decrypts
ciphertext produced by `notabene-e2ee-js` from a checked-in vector, so a drift in the ConcatKDF
inputs, the AAD, or the JSON serialisation fails the build. No Node needed to run it.

Key files use the same format, so `keys/vaspB.json` can be moved between the two projects.

```bash
mvn test
```

## A React client

[notabene-e2ee-ui](../notabene-e2ee-ui) is a React console for this API: transfers per VASP or all
together, ciphertext next to decrypted PII, and an editable IVMS101 send form.

## Configuration

All of `application.yml` is overridable by environment variable.

> **Keep credentials out of the repo.** `application.yml` is tracked and this repo is public, so
> leave `client-id` / `client-secret` as empty `${VASP_A_CLIENT_ID:}` placeholders there. Real values
> belong in `config/application.yml` (gitignored, loaded ahead of the packaged file by Spring Boot)
> or in environment variables.

| Property | Default | Notes |
|---|---|---|
| `notabene.api-base` | `https://sandbox.notabene.id` | production: `https://eu-a.notabene.id` or `https://us-a.notabene.id` |
| `notabene.auth-url` | `https://auth.notabene.id/oauth/token` | US production: `https://us.auth.notabene.id/oauth/token` |
| `notabene.audience` | = `api-base` | |
| `notabene.pii-mode` | `branch` | `branch` or `field` |
| `notabene.key-dir` | `keys` | `keys/<vasp>.json`, gitignored |
| `notabene.key-fragment` | `pii` | DIDDoc key id suffix |
| `notabene.polling.*` | 15s, limit 25, `incoming` | interval, page size, direction, history size |
| `notabene.vasps.<name>.*` | vaspA, vaspB | `did`, `client-id`, `client-secret`, `customer-id` (optional) — add as many as you like |

## Logging

Every outbound call — Notabene's API and its OAuth endpoint — is logged by the `notabene.http` logger
at `DEBUG` (on by default in `application.yml`): the request line and body, then the status, timing and
response body. The `Authorization` header is never logged, and `client_secret` / `access_token` values
in JSON bodies are masked. Bodies over 10,000 characters are truncated. Presentations carry JWE
ciphertext only, so they are safe to log.

```yaml
logging.level.notabene.http: INFO   # switch it off
```

## Layout

| Path | What it does |
|---|---|
| `crypto/EcdhEsJwe.java` | The JWE. ECDH-ES + ConcatKDF + AES-GCM, encrypt and decrypt. |
| `crypto/P256.java` | Keygen, JWK ↔ JCA, SEC1 point decode with curve validation. |
| `crypto/PiiCrypto.java` | The JSON-serialising wrappers Notabene interoperates with. |
| `ivms/IvmsCrypto.java` | branch/field encryption, auto-detecting decryption, IVMS lookup. |
| `notabene/NotabeneClient.java` | REST client: public keys, create transfer, present PII, get/list transfers. |
| `service/DemoService.java` | The offline round trip behind `/api/demo`. |
| `service/TravelRuleService.java` | `/api/send`. |
| `service/PollingService.java` | `/api/startPool` and `/api/stopPool`. |
| `service/AddressOwnershipService.java` | register (initiate/complete), registration-status, and attestation/proof building. |
| `tools/sign-attestation.mjs` | Node helper that EIP-191-signs an attestation, for testing proofs. |

## Notes and gotchas

- **v2.1 only.** This project targets Notabene's v2.1 API (`/api/v1/...`, no entity DID in URLs). The old
  v2.0 calls (`/entities/{did}/...`, relationships, `address-ownership/discover`) are gone.
- **Open v2.1 questions.** There is no public-keys endpoint, so the recipient key comes from
  `POST /api/v1/transfers/assess?include_pubkeys=true`. The docs disagree on the IVMS envelope
  (`originatorPerson` in the encryption guide, `naturalPerson` in the reference); we encrypt the
  `originator` / `beneficiary` branch of `sample-pii.json` as is. `include_ivms` may need the
  `read:customer:pii` permission.
- **Spring Boot 4 does not auto-configure `RestClient.Builder`**, so `HttpClientConfig` provides one
  with timeouts.
- **Jackson 3.** Spring Boot 4 ships `tools.jackson.*`, not `com.fasterxml.jackson.*`, and its
  exceptions are unchecked. Worth knowing before adding a dependency that expects Jackson 2.
- **`crit` in Notabene's reference.** Their TypeScript example adds `crit: ["apu","apv"]` to the JWE
  header. RFC 7515 forbids registered parameters there, so this project omits it; the decryptor
  ignores a `crit` header on input, so their ciphertext still decrypts here.
- **Notabene's platform-managed ciphertext** uses a different header shape (`alg: dir` with
  `senderKid`/`recipientKid`). This project implements the customer-managed `ECDH-ES` scheme.
