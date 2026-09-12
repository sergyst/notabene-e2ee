# Notabene Travel Rule — end-to-end encrypted PII (Java / Spring Boot)

A Spring Boot port of the JavaScript project, where **you** own the encryption:

- **vaspA** encrypts IVMS101 PII with its own code and posts only ciphertext to Notabene.
- **vaspB** pulls the transfer with `decrypt=false` and decrypts locally with a private key that never leaves it.
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
  -d '{"from":"vaspA","to":"vaspB"}' | jq
```

| Field | Required | Meaning |
|---|---|---|
| `from` / `to` | yes | configured VASP names, e.g. `vaspA`, `vaspB` |
| `mode` | no | `branch` (default) or `field` |
| `transferId` | no | present PII on an existing transfer instead of creating one |
| `policyId` | no | fulfil one specific policy instead of every open one |
| `originatorId` / `beneficiaryId` | no | party identifiers on the transfer |
| `pii` | no | your own IVMS101 object; defaults to `sample-pii.json` |

It fetches vaspB's published key, creates the transfer, encrypts locally, and POSTs the ciphertext.

### startPool / stopPool

```bash
curl -s -X POST localhost:8080/api/startPool \
  -H 'Content-Type: application/json' \
  -d '{"vasp":"vaspB","intervalSeconds":15}' | jq

curl -s localhost:8080/api/pollStatus | jq
curl -s -X POST localhost:8080/api/stopPool -H 'Content-Type: application/json' -d '{"vasp":"vaspB"}'
```

The poller lists incoming transfers, fetches each new one with `decrypt=false`, decrypts it with that
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
  -d '{"from":"vaspA","to":"vaspB"}' | jq '{transferId, recipientKid, warning}'
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
{ "ivms101": { "originator": "eyJhbGciOiJFQ0RILUVTIiwi...", "beneficiary": "eyJhbGciOiJFQ0RILUVTIiwi..." } }
```

Two JWEs instead of fifteen, and the structure leaks nothing.

**`field`** — every leaf value becomes its own JWE, the IVMS101 tree stays visible. This is the shape
in Notabene's own reference examples, and the only one that lets the platform validate a payload it
cannot read. If you ever set `notabene.skip-validation: false` and a branch-mode payload is rejected,
that is why.

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

## Configuration

All of `application.yml` is overridable by environment variable.

| Property | Default | Notes |
|---|---|---|
| `notabene.api-base` | `https://api.eu1.notabene.id` | US node: `https://api.us1.notabene.id` |
| `notabene.auth-url` | `https://auth.notabene.id/oauth/token` | US: `https://us.auth.notabene.id/oauth/token` |
| `notabene.audience` | = `api-base` | |
| `notabene.pii-mode` | `branch` | `branch` or `field` |
| `notabene.key-dir` | `keys` | `keys/<vasp>.json`, gitignored |
| `notabene.key-fragment` | `pii` | DIDDoc key id suffix |
| `notabene.skip-validation` | `true` | `skipValidation` on the presentation call |
| `notabene.polling.*` | 15s, limit 25, `incoming` | interval, page size, direction, history size |
| `notabene.vasps.<name>.*` | vaspA, vaspB | `did`, `client-id`, `client-secret` — add as many as you like |

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

## Notes and gotchas

- **Path spellings.** Notabene's prose docs use `/entity/:did/...` while the OpenAPI spec uses
  `/entities/{entityDID}/...`, and the presentation endpoint appears as both `/tx/:id/presentation`
  and `/transfers/:id/policies/:policyId/presentation`. `NotabeneClient` tries the documented variants
  in order and logs which one answered.
- **Spring Boot 4 does not auto-configure `RestClient.Builder`**, so `HttpClientConfig` provides one
  with timeouts.
- **Jackson 3.** Spring Boot 4 ships `tools.jackson.*`, not `com.fasterxml.jackson.*`, and its
  exceptions are unchecked. Worth knowing before adding a dependency that expects Jackson 2.
- **`crit` in Notabene's reference.** Their TypeScript example adds `crit: ["apu","apv"]` to the JWE
  header. RFC 7515 forbids registered parameters there, so this project omits it; the decryptor
  ignores a `crit` header on input, so their ciphertext still decrypts here.
- **Notabene's platform-managed ciphertext** uses a different header shape (`alg: dir` with
  `senderKid`/`recipientKid`). This project implements the customer-managed `ECDH-ES` scheme.
