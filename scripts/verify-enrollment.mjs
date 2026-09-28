// Independently reproduce the public synthetic vector with Node/OpenSSL, then
// compare an optional Rust example output. No real credentials or network access.
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';

const vector = JSON.parse(readFileSync(new URL('../crates/mitigate-enrollment/fixtures/enrollment-v1.json', import.meta.url), 'utf8'));
const privateKey = createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 23)]),
  format: 'der', type: 'pkcs8',
});
const publicKey = createPublicKey(privateKey);
const publicBytes = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
const token = Buffer.alloc(32, 41);
const claim = {
  grant_id: '00000000-0000-4000-8000-000000000001',
  token: token.toString('base64url'),
  public_key: publicBytes.toString('base64url'),
  runtime_ref: 'ref_11111111111111111111111111111111',
  enrollment_ref: 'ref_22222222222222222222222222222222',
};
const fields = ['mitigate.runtime.enrollment.v1', 'https://mitigate.example', claim.grant_id,
  createHash('sha256').update(token).digest('base64url'), claim.public_key, claim.runtime_ref, claim.enrollment_ref];
const message = Buffer.from(`${fields.join('\n')}\n`);
const signature = sign(null, message, privateKey);
claim.signature = signature.toString('base64url');
assert(verify(null, message, publicKey, signature));
assert.equal(vector.origin, fields[1]);
assert.deepEqual(vector.claim, claim);
for (let i = 0; i < fields.length; i++) {
  const changed = [...fields];
  changed[i] += 'x';
  assert.equal(verify(null, Buffer.from(`${changed.join('\n')}\n`), publicKey, signature), false);
}
assert.equal(verify(null, message.subarray(0, -1), publicKey, signature), false);
if (process.argv.length > 3) throw new Error('Use at most one synthetic Rust output path.');
if (process.argv[2]) assert.deepEqual(JSON.parse(readFileSync(process.argv[2], 'utf8')), claim);
console.log('Enrollment fixture: independent OpenSSL proof and field-binding checks passed.');
