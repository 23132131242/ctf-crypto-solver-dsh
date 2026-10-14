#!/usr/bin/env node
import { readFileSync, statSync } from 'node:fs';

function parseNumber(value, label) {
  if (typeof value !== 'string' || !/^(?:0x[0-9a-f]+|[0-9]+)$/i.test(value)) {
    throw new Error(`${label} must be a decimal or 0x hexadecimal string`);
  }
  const n = BigInt(value);
  if (n < 0n || n.toString(2).length > 8192) throw new Error(`${label} out of range`);
  return n;
}
function gcd(a, b) {
  while (b !== 0n) [a, b] = [b, a % b];
  return a;
}
function isqrt(n) {
  if (n < 0n) throw new Error('negative square root');
  if (n < 2n) return n;
  let x = 1n << BigInt(Math.ceil(n.toString(2).length / 2));
  while (true) {
    const y = (x + n / x) >> 1n;
    if (y >= x) return x;
    x = y;
  }
}
function iroot(n, exponent) {
  let lo = 0n;
  let hi = 1n << BigInt(Math.ceil(n.toString(2).length / Number(exponent)) + 1);
  while (lo + 1n < hi) {
    const mid = (lo + hi) >> 1n;
    if (mid ** exponent <= n) lo = mid;
    else hi = mid;
  }
  return lo;
}
function powmod(base, power, modulus) {
  let result = 1n;
  for (base %= modulus; power > 0n; power >>= 1n) {
    if (power & 1n) result = result * base % modulus;
    base = base * base % modulus;
  }
  return result;
}
function inv(a, m) {
  let [oldR, r, oldS, s] = [m, a, 0n, 1n];
  while (r) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  return oldR === 1n ? (oldS % m + m) % m : null;
}
function wiener(n, e) {
  let [numerator, denominator] = [e, n];
  let [prev2n, prev1n, prev2d, prev1d] = [0n, 1n, 1n, 0n];
  while (denominator) {
    const a = numerator / denominator;
    const [k, d] = [a * prev1n + prev2n, a * prev1d + prev2d];
    if (k && (e * d - 1n) % k === 0n) {
      const phi = (e * d - 1n) / k;
      const sum = n - phi + 1n;
      const discr = sum * sum - 4n * n;
      if (discr >= 0n) {
        const root = isqrt(discr);
        if (root * root === discr && (sum + root) % 2n === 0n) {
          const p = (sum + root) / 2n;
          const q = (sum - root) / 2n;
          if (p > 1n && q > 1n && p * q === n) return { p, q, d };
        }
      }
    }
    [prev2n, prev1n, prev2d, prev1d] = [prev1n, k, prev1d, d];
    [numerator, denominator] = [denominator, numerator % denominator];
  }
  return null;
}
function fermat(n, maxSteps) {
  if ((n & 1n) === 0n) return { p: 2n, q: n / 2n, steps: 0 };
  let a = isqrt(n);
  if (a * a < n) a++;
  for (let step = 0; step <= maxSteps; step++, a++) {
    const delta = a * a - n;
    const b = isqrt(delta);
    if (b * b === delta && a - b > 1n) return { p: a - b, q: a + b, steps: step };
  }
  return null;
}
function showMessage(m) {
  const hex = m.toString(16).padStart(2, '0');
  const bytes = Buffer.from(hex.length % 2 ? `0${hex}` : hex, 'hex');
  let utf8 = null;
  try {
    const decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    if (!/[\u0000-\u001f\u007f]/u.test(decoded)) utf8 = decoded;
  } catch { /* binary */ }
  return { decimal: m.toString(), hex: `0x${hex}`, utf8, note: 'leading zero bytes and RSA padding are not inferred' };
}
function main(argv) {
  if (argv.length !== 2 && argv.length !== 4) throw new Error('usage: node rsa-triage.mjs --input params.json|- [--max-fermat 10000]');
  if (argv[0] !== '--input' || (argv.length === 4 && argv[2] !== '--max-fermat')) throw new Error('invalid arguments');
  const maxFermat = argv.length === 4 ? Number(argv[3]) : 1000;
  if (!Number.isInteger(maxFermat) || maxFermat < 0 || maxFermat > 100000) throw new Error('--max-fermat must be 0..100000');
  if (argv[1] !== '-' && statSync(argv[1]).size > 1048576) throw new Error('input exceeds 1 MiB');
  const text = readFileSync(argv[1] === '-' ? 0 : argv[1], 'utf8');
  if (Buffer.byteLength(text, 'utf8') > 1048576) throw new Error('input exceeds 1 MiB');
  const data = JSON.parse(text);
  if (data === null || Array.isArray(data) || typeof data !== 'object') throw new Error('expected JSON object');
  const n = parseNumber(data.n, 'n');
  const e = parseNumber(data.e, 'e');
  const c = data.c === undefined ? null : parseNumber(data.c, 'c');
  if (n <= 2n || e <= 1n || e >= n) throw new Error('expected n > e > 1');
  if (c !== null && c >= n) throw new Error('c must be less than n');
  const result = { input: { nBits: n.toString(2).length, e: e.toString(), hasCiphertext: c !== null }, checks: [], candidates: [] };
  if (c !== null) {
    const g = gcd(c, n);
    result.checks.push({ method: 'gcd(c,n)', outcome: g > 1n && g < n ? `nontrivial factor ${g}` : `gcd=${g}` });
    if (g > 1n && g < n) result.candidates.push({ method: 'gcd(c,n)', p: g.toString(), q: (n / g).toString() });
    if (e <= 5n) {
      const m = iroot(c, e);
      const valid = m ** e === c && powmod(m, e, n) === c;
      result.checks.push({ method: 'exact-small-exponent-root', outcome: valid ? 'exact root' : 'not exact' });
      if (valid) result.candidates.push({ method: 'exact-small-exponent-root', message: showMessage(m), reencrypts: true });
    }
  }
  const w = wiener(n, e);
  result.checks.push({ method: 'wiener', outcome: w ? 'factor candidate' : 'no candidate' });
  if (w) result.candidates.push({ method: 'wiener', p: w.p.toString(), q: w.q.toString(), d: w.d.toString() });
  const f = fermat(n, maxFermat);
  result.checks.push({ method: 'bounded-fermat', limit: maxFermat, outcome: f ? `factor candidate in ${f.steps} steps` : 'no candidate within limit' });
  if (f) result.candidates.push({ method: 'bounded-fermat', p: f.p.toString(), q: f.q.toString() });
  if (c !== null) {
    for (const candidate of result.candidates) {
      if (!candidate.p) continue;
      const p = BigInt(candidate.p), q = BigInt(candidate.q);
      if (p * q !== n || p <= 1n || q <= 1n) continue;
      const d = inv(e, (p - 1n) * (q - 1n));
      if (d === null) continue;
      const m = powmod(c, d, n);
      if (powmod(m, e, n) === c) {
        candidate.message = showMessage(m);
        candidate.reencrypts = true;
        candidate.note = 'Factor primality and any padding/encoding need independent validation';
      }
    }
  }
  console.log(JSON.stringify(result, null, 2));
}
try { main(process.argv.slice(2)); }
catch (error) { console.error(`rsa-triage: ${error.message}`); process.exitCode = 1; }
