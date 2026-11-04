# Flows

Three situations you will actually be in, end to end. Endpoint reference is in the [README](../README.md);
this file is about *when* to call what, and what happens behind each call.

Names used below: `vaspA` / `vaspB` are VASPs configured on this server. "Notabene" is the directory
and message broker — it never sees plaintext PII.

---

## Flow 1 — I created a wallet (address A) and must register it in Notabene

**Why.** Counterparties find out who owns an address by asking Notabene. An address nobody has
registered is an address nobody will send Travel Rule PII about. Registering says: *"this address
belongs to my VASP's DID."*

**Who calls.** The VASP that controls the private key of address A.

### Steps

1. **Pick the network explicitly.** The same `0x…` on two chains is two different registrations, so
   there is no default. `ethereum`, `polygon`, `bitcoin`, … or a CAIP-2 id like `eip155:42161`.
   (Testnets are rejected by Notabene — see the README.)

2. **Check the current state** (optional but cheap):

   ```bash
   curl -s "localhost:8080/api/registration-status?vasp=vaspA&address=0xA…&network=ethereum" | jq
   ```

   `{"registered": false}` means nobody owns it yet.

3. **Registration is always proven.** A bare self-declaration ("the claimant says so") would let
   any VASP claim any address, so this server does not offer it. Notabene verifies a signature made
   with the address's private key. The address is always registered to the calling VASP's own DID.

   > **Unverified:** which status Notabene then reports for a proven registration (`PROVEN`?
   > `CONFIRMED`?) has not been checked against a live call. Register one in the sandbox and read the
   > real `confidence` value.

4. **Initiate — get the message to sign.** It embeds a timestamp, so fetch it once and sign *that
   exact string* — do not rebuild it later.

   ```bash
   curl -s "localhost:8080/api/register/initiate?vasp=vaspA&address=0xA…&network=ethereum" | jq
   ```

   ```
   I certify that

   eip155:1 account 0xA…

   belonged to did:web:…vaspA

   on Thu, 04 Dec 2025 14:20:12 GMT
   ```

5. **Sign it with address A's private key** (EIP-191 `personal_sign`). This server never
   holds that key. For testing, `tools/sign-attestation.mjs` does it:

   ```bash
   cd tools && npm install
   node sign-attestation.mjs --key 0x<privkey> --message "<the attestation text>"
   ```

6. **Complete — register with the proof.**

   ```bash
   curl -s -X POST localhost:8080/api/register/complete -H 'Content-Type: application/json' -d '{
     "vasp":"vaspA", "address":"0xA…", "network":"ethereum",
     "proof":{"type":"eip-191","attestation":"<exact text>","signature":"0x…"}}' | jq
   ```

7. **Confirm.** The response already contains the re-checked status; or call `registration-status`
   again. You want `registered: true` and your VASP's DID as the owner.

### What happens inside

`AddressOwnershipService.register` (behind `POST /api/register/complete`) → builds CAIP-10 (`eip155:1:0xA…`) → `PATCH
/entities/{yourDID}/relationships?from=did:pkh:<caip10>&to=<yourDID>` with the proof as body →
re-runs discovery. The `proof.did` is the *address* (`did:pkh:…`), not the owner — Notabene rejects a
mismatch with "Proof did does not match 'from' query".

This server does not verify the signature; Notabene does. A bad signature comes back as a Notabene
error (502 `notabene_api_error`).

### Common failures

| Symptom | Cause |
|---|---|
| 400 "Address names chain X but network is Y" | the address already carried a chain prefix that disagrees with `network` |
| Notabene error about asset / chain | testnet network, or unsupported chain |
| 400 `proof must not be null` / `proof.signature must not be blank` | the proof, or one of its two required fields, is missing |

---

## Flow 2 — I sent tokens from A to B; who do I send the Travel Rule message to?

You are the **originator VASP**. You know the destination address B but not which VASP holds its
private key. Notabene can tell you — *if* that VASP registered the address (their Flow 1).

### Steps

1. **Discover the owner of B.**

   ```bash
   curl -s "localhost:8080/api/registration-status?vasp=vaspA&address=0xB…&network=ethereum" | jq
   ```

   The answer is the **beneficiary VASP**: its DID, name, jurisdiction, and — if it is one of your
   configured VASPs — its local name. `confidence` tells you how much to trust it:

   | `confidence` | Meaning |
   |---|---|
   | `CONFIRMED` | owner registered it (Flow 1). Whether a *proven* registration reports a different value is unverified. |
   | `UNCONFIRMED` | Notabene inferred it (hashed-address service, analytics) — treat with care |
   | `NOT_FOUND` | nobody has claimed it. **You cannot send.** Ask the customer/counterparty, or use another channel. |

2. **Send.** You only pass the address; the server asks Notabene who owns it (there is no `to` field):

   ```bash
   curl -s -X POST localhost:8080/api/send -H 'Content-Type: application/json' -d '{
     "from":"vaspA",
     "beneficiaryAddress":"eip155:1:0xB…",
     "asset":"eip155:1/slip44:60",
     "pii": { …your IVMS101… }
   }' | jq '{transferId, beneficiary, beneficiaryDid, discoveredFrom, recipientKid, warning}'
   ```

   Give the address in CAIP-10 form (as above) so the chain is unambiguous. `discoveredFrom` in the
   response echoes the address the beneficiary was discovered from.

   If nobody owns the address the call fails with 400 *"No VASP owns … The owner must register it
   first"* — nothing is sent.

3. **What `send` does with the discovered DID**

   1. **Find the key to encrypt to.** Asks Notabene for the beneficiary's public encryption keys
      (`/entities/{did}/public-keys`).
   2. **Create the transfer** (originator → beneficiary DID, asset, amount, addresses).
   3. **Encrypt locally** with ECDH-ES + AES-256-GCM, bound to your DID (`apu`) and the recipient
      key id (`apv`). Plaintext never leaves this process.
   4. **Present the ciphertext** to Notabene, which routes it to the beneficiary VASP.

4. **Check the warning.** `recipientKid` should end in `#pii` (their own key). If it ends in
   `#notabene-pii`, or `warning` is set, the beneficiary has not published their own key and Notabene
   can read the PII — that is not end-to-end. See "Setting up test VASPs" in the README.

### Which IVMS101 do I send?

`pii` is your IVMS101 object (default: `sample-pii.json`) with `originator` and `beneficiary`
branches. Before sending, make sure it is complete — see the validation checklist in Flow 3; the
same rules apply to what you emit.

---

## Flow 3 — I received a Travel Rule message and must validate it

You are the **beneficiary VASP**. Someone sent PII about a transfer to an address you registered.

### Step A — receive and decrypt (implemented)

1. **Get notified.** Either poll:

   ```bash
   curl -s -X POST localhost:8080/api/startPool -H 'Content-Type: application/json' -d '{"vasp":"vaspB"}'
   curl -s localhost:8080/api/pollStatus | jq '.[0].recent'
   ```

   or list on demand: `GET /api/transfers?vasp=vaspB&direction=incoming`. (In production prefer
   Notabene's `tap.requirePresentationSatisfied` webhook; polling just needs no public URL.)

2. **Fetch one transfer with `decrypt=false`** — we want the ciphertext, not Notabene's copy:

   ```bash
   curl -s "localhost:8080/api/transfers/<id>?vasp=vaspB" | jq
   ```

3. **Decrypt locally** with your private key (`keys/vaspB.json`). Per JWE, the decryptor checks:
   - the ephemeral key in the header is a valid P-256 point,
   - `apv` equals `SHA-256` of *your* key id (the message was meant for this key),
   - `apu` equals `SHA-256` of the sender DID (it came from who it says),
   - the AES-GCM tag (nothing was tampered with, including the header).

   Branch and field mode are auto-detected. A failure here means the message was not encrypted to
   your key, or was altered — **reject it**.

### Step B — validate the IVMS101 content (**not implemented yet**)

Decryption proves the message is intact and addressed to you. It does **not** prove the *content* is
a valid IVMS101 document — today the decrypted JSON is returned and logged as-is, with no schema
check. What a validator should assert (this is the work to build):

| Check | Rule |
|---|---|
| Shape | top-level `originator` and `beneficiary`; `originator.originatorPersons[]` and `beneficiary.beneficiaryPersons[]` non-empty |
| Person | each person is exactly one of `naturalPerson` / `legalPerson` |
| Natural person name | `name.nameIdentifier[]` with `primaryIdentifier` set and a `nameIdentifierType` from the IVMS101 enum (`LEGL`, `ALIA`, `BIRT`, `MAID`, `OTHR`) |
| Legal person name | `name.nameIdentifier[].legalPersonName` + `legalPersonNameIdentifierType` (`LEGL`, `SHRT`, `TRAD`) |
| Account | `accountNumber[]` present on both sides; the beneficiary's should match the address you registered |
| Geographic address | `addressType` from enum (`HOME`, `BIZZ`, `GEOG`), ISO-3166 alpha-2 `country`, `addressLine[]` or street fields |
| Dates & places | `dateOfBirth` is `YYYY-MM-DD` and in the past; `countryOfBirth` ISO-3166 alpha-2 |
| National id | `nationalIdentifierType` from enum (`ARNU`, `CCPT`, `RAID`, `DRLC`, `FIIN`, `TXID`, `SOCS`, `IDCD`, `LEIX`, `MISC`), `countryOfIssue` ISO alpha-2, LEI format for `LEIX` |
| Consistency with the transfer | beneficiary account = an address you own; amount/asset on the transfer match what you expected |
| Encoding | strings are valid UTF-8 and within IVMS101 length limits (names ≤ 100, address lines ≤ 70) |

Recommended outcome model: validate → if all pass, accept; if structural errors, **reject and tell
the originator what failed** (don't silently drop); if only soft issues (e.g. missing optional
fields), accept with warnings recorded. Validate *after* decryption and *before* you act on the data
(screening, matching to a customer, crediting).

In field mode, validate the reassembled tree, not the individual leaves.

### Matching to your customer

After the structure is valid, compare `beneficiary` name/account with the customer who owns the
address — that is the compliance decision (accept / hold / return), and it belongs to your own
screening pipeline, not to this demo.

---

## Quick map

| I want to… | Call |
|---|---|
| Claim an address | `GET /api/register/initiate` → sign → `POST /api/register/complete` |
| See who owns an address | `GET /api/registration-status` |
| Send PII to an address's owner | `POST /api/send` with `beneficiaryAddress` |
| Receive and decrypt | `POST /api/startPool` or `GET /api/transfers/{id}` |
| Validate received IVMS101 | *not built yet* — see Flow 3, step B |
