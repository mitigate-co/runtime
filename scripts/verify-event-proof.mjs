// Independent Node/OpenSSL verification of the public synthetic Rust event.
// No real credentials, native store, network or production canonicalizer.
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';

if (process.argv.length !== 3 && !(process.argv.length === 4 && process.argv[3] === '--inventory'))
  throw new Error('Provide the synthetic Rust event output path and optional --inventory.');
const actual = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const inventory = process.argv[3] === '--inventory';
const event = JSON.parse(readFileSync(new URL(inventory ? '../examples/egress/inventory-part.json' : '../examples/egress/decision.json', import.meta.url), 'utf8'));
// This fixture contains ASCII keys and safe integers only. Sorting object keys
// reproduces its RFC 8785 bytes independently of the Rust implementation.
function canonical(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    assert(Number.isSafeInteger(value));
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const keys = Object.keys(value).sort();
  assert(keys.every(key => /^[a-z_]+$/.test(key)));
  return `{${keys.map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}
const privateKey = createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 23)]),
  format: 'der', type: 'pkcs8',
});
const publicKey = createPublicKey(privateKey);
const origin = 'https://mitigate.example';
const enrollmentRef = 'ref_99999999999999999999999999999999';
const digest = createHash('sha256').update(canonical(event)).digest('base64url');
const fields = ['mitigate.runtime.event.v1', origin, 'POST', '/api/v1/runtime/events',
  event.runtime_ref, enrollmentRef, event.event_id, digest];
const message = Buffer.from(`${fields.join('\n')}\n`);
const signature = sign(null, message, privateKey);
assert.deepEqual(actual, {
  schema_version: 1, enrollment_ref: enrollmentRef, event,
  signature: signature.toString('base64url'),
});
assert(verify(null, message, publicKey, Buffer.from(actual.signature, 'base64url')));
for (let i = 0; i < fields.length; i++) {
  const changed = [...fields];
  changed[i] += 'x';
  assert.equal(verify(null, Buffer.from(`${changed.join('\n')}\n`), publicKey, signature), false);
}
assert.equal(verify(null, message.subarray(0, -1), publicKey, signature), false);
// Tampering with each event field, including otherwise valid decision facts,
// cannot reuse the original signature. Hash only this known public fixture.
for (const field of Object.keys(event)) {
  const changed = structuredClone(event);
  changed[field] = null;
  const altered = [...fields];
  altered[7] = createHash('sha256').update(canonical(changed)).digest('base64url');
  assert.equal(verify(null, Buffer.from(`${altered.join('\n')}\n`), publicKey, signature), false);
}
for (const field of Object.keys(event.facts)) {
  const changed = structuredClone(event);
  changed.facts[field] = changed.facts[field] === null ? 1 : null;
  const altered = [...fields];
  altered[7] = createHash('sha256').update(canonical(changed)).digest('base64url');
  assert.equal(verify(null, Buffer.from(`${altered.join('\n')}\n`), publicKey, signature), false);
}
const damaged = Buffer.from(signature);
if (inventory) {
  for (const field of Object.keys(event.facts.tools[0])) {
    const changed = structuredClone(event);
    changed.facts.tools[0][field] = null;
    const altered = [...fields];
    altered[7] = createHash('sha256').update(canonical(changed)).digest('base64url');
    assert.equal(verify(null, Buffer.from(`${altered.join('\n')}\n`), publicKey, signature), false);
  }
}
damaged[0] ^= 1;
assert.equal(verify(null, message, publicKey, damaged), false);
console.log('Event fixture: independent OpenSSL signature, exact body and tamper checks passed.');
