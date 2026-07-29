import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normaliseDomain, mailSignals, mapLimit, unquoteTxt } from './lib.js';

test('unquoteTxt strips surrounding quotes', () => {
  assert.equal(unquoteTxt('"v=spf1 include:_spf.google.com ~all"'), 'v=spf1 include:_spf.google.com ~all');
});

test('unquoteTxt concatenates a record split into multiple quoted chunks', () => {
  // DNS splits strings over 255 chars; DoH returns them as adjacent quoted chunks.
  assert.equal(unquoteTxt('"v=spf1 ip4:1.2.3.4 " "include:example.com ~all"'), 'v=spf1 ip4:1.2.3.4 include:example.com ~all');
});

test('unquoteTxt passes through an unquoted string', () => {
  assert.equal(unquoteTxt('v=DMARC1; p=reject'), 'v=DMARC1; p=reject');
});

test('normaliseDomain accepts a bare domain', () => {
  const r = normaliseDomain('apify.com');
  assert.equal(r.ok, true);
  assert.equal(r.domain, 'apify.com');
});

test('normaliseDomain reduces a full URL to its hostname', () => {
  const r = normaliseDomain('https://www.github.com/features/actions?x=1');
  assert.equal(r.ok, true);
  assert.equal(r.domain, 'github.com');
});

test('normaliseDomain strips a leading www and uppercases', () => {
  const r = normaliseDomain('WWW.Example.CO.UK');
  assert.equal(r.ok, true);
  assert.equal(r.domain, 'example.co.uk');
});

test('normaliseDomain strips a port', () => {
  const r = normaliseDomain('example.com:8443');
  assert.equal(r.ok, true);
  assert.equal(r.domain, 'example.com');
});

test('normaliseDomain rejects empty input', () => {
  assert.equal(normaliseDomain('').ok, false);
  assert.equal(normaliseDomain(null).ok, false);
});

test('normaliseDomain rejects a string with no TLD', () => {
  assert.equal(normaliseDomain('localhost').ok, false);
});

test('normaliseDomain rejects a leading hyphen label', () => {
  assert.equal(normaliseDomain('-bad.com').ok, false);
});

test('mailSignals identifies Google Workspace from MX', () => {
  const s = mailSignals({ mx: ['1 aspmx.l.google.com', '5 alt1.aspmx.l.google.com'], txt: [] });
  assert.equal(s.mailProvider, 'Google Workspace');
  assert.equal(s.hasMx, true);
});

test('mailSignals identifies Microsoft 365 from MX', () => {
  const s = mailSignals({ mx: ['0 contoso-com.mail.protection.outlook.com'], txt: [] });
  assert.equal(s.mailProvider, 'Microsoft 365');
});

test('mailSignals reports no MX when the list is empty', () => {
  const s = mailSignals({ mx: [], txt: [] });
  assert.equal(s.hasMx, false);
  assert.equal(s.mailProvider, null);
});

test('mailSignals extracts an SPF record', () => {
  const s = mailSignals({ mx: [], txt: ['v=spf1 include:_spf.google.com ~all', 'some-other-txt'] });
  assert.equal(s.spf, 'v=spf1 include:_spf.google.com ~all');
});

test('mailSignals returns null SPF when absent', () => {
  const s = mailSignals({ mx: [], txt: ['google-site-verification=abc'] });
  assert.equal(s.spf, null);
});

test('mapLimit preserves input order regardless of completion order', async () => {
  const delays = [30, 5, 20, 1];
  const out = await mapLimit(delays, 2, async (d, i) => {
    await new Promise((r) => setTimeout(r, d));
    return i;
  });
  assert.deepEqual(out, [0, 1, 2, 3]);
});

test('mapLimit handles an empty list', async () => {
  assert.deepEqual(await mapLimit([], 4, async (x) => x), []);
});

test('mapLimit respects the concurrency ceiling', async () => {
  let active = 0;
  let peak = 0;
  await mapLimit([1, 2, 3, 4, 5, 6, 7, 8], 3, async (x) => {
    active += 1;
    peak = Math.max(peak, active);
    await new Promise((r) => setTimeout(r, 5));
    active -= 1;
    return x;
  });
  assert.ok(peak <= 3, `peak concurrency was ${peak}, expected <= 3`);
});
