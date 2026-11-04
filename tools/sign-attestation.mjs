/**
 * Sign an address-ownership attestation (EIP-191 personal_sign).
 *
 * The Java server cannot do this itself: keccak-256 is not SHA3-256, and the
 * JDK dropped secp256k1 from SunEC, so signing would mean pulling in
 * BouncyCastle. Signing belongs with whatever custodies the key anyway.
 *
 *   node sign-attestation.mjs --key 0x<privkey> --message "I certify that…"
 *   node sign-attestation.mjs --new                     # throwaway key, for testing
 *
 * Prints the address the key controls and the signature to send as
 * proof.signature.
 */
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, arg, i, all) => {
    if (arg.startsWith('--')) {
      const next = all[i + 1];
      // A flag with nothing after it, or followed by another flag, is a boolean.
      acc.push([arg.slice(2), next === undefined || next.startsWith('--') ? true : next]);
    }
    return acc;
  }, []),
);

const hex = (bytes) => '0x' + Buffer.from(bytes).toString('hex');
const unhex = (s) => Uint8Array.from(Buffer.from(s.replace(/^0x/, ''), 'hex'));

/** Ethereum address = last 20 bytes of keccak256(uncompressed pubkey minus its 0x04 tag). */
function addressFor(privateKey) {
  const pub = secp256k1.getPublicKey(privateKey, false).slice(1);
  return hex(keccak_256(pub).slice(-20));
}

/** EIP-191: keccak256("\x19Ethereum Signed Message:\n" + byteLength + message). */
function personalSignHash(message) {
  const body = new TextEncoder().encode(message);
  const prefix = new TextEncoder().encode(`\x19Ethereum Signed Message:\n${body.length}`);
  return keccak_256(Uint8Array.from([...prefix, ...body]));
}

function sign(privateKey, message) {
  const sig = secp256k1.sign(personalSignHash(message), privateKey, { prehash: false });
  // 65 bytes: r || s || v, with v = 27 + recovery, as eth_sign returns.
  return hex(Uint8Array.from([...sig.toBytes('compact'), 27 + sig.recovery]));
}

const privateKey = args.new === true ? secp256k1.utils.randomSecretKey() : unhex(typeof args.key === 'string' ? args.key : '');
if (!privateKey.length) {
  console.error('Give --key 0x<private key>, or --new for a throwaway one.');
  process.exit(1);
}

const address = addressFor(privateKey);
if (typeof args.message !== 'string' || !args.message) {
  console.log(JSON.stringify({ address, privateKey: args.new === true ? hex(privateKey) : '(not shown)' }, null, 2));
  console.error('\nNo --message given, so nothing was signed.');
  process.exit(0);
}

console.log(JSON.stringify({
  address,
  ...(args.new === true ? { privateKey: hex(privateKey) } : {}),
  type: 'eip-191',
  attestation: args.message,
  signature: sign(privateKey, args.message),
}, null, 2));
