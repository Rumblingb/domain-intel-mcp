import { Actor, log } from 'apify';
import { inspectDomain, mapLimit } from './lib.js';

await Actor.init();

const input = (await Actor.getInput()) ?? {};
const {
  domains = [],
  includeSsl = true,
  includeRdap = true,
  sslTimeoutMs = 8000,
  rdapTimeoutMs = 10000,
  maxConcurrency = 8,
} = input;

const list = (Array.isArray(domains) ? domains : [domains])
  .map((d) => String(d ?? '').trim())
  .filter((d) => d.length > 0);

if (list.length === 0) {
  await Actor.fail('No domains supplied. Provide a "domains" array with at least one entry.');
}

log.info(`Inspecting ${list.length} domain(s) | ssl=${includeSsl} rdap=${includeRdap} concurrency=${maxConcurrency}`);

let done = 0;
const results = await mapLimit(list, Math.max(1, maxConcurrency), async (domain) => {
  const result = await inspectDomain(domain, { includeSsl, includeRdap, sslTimeoutMs, rdapTimeoutMs });
  await Actor.pushData(result);

  // Pay-per-event. No-ops when the Actor is not on a PPE pricing model.
  try {
    await Actor.charge({ eventName: 'domain-inspected' });
  } catch (err) {
    log.debug(`charge skipped: ${err.message}`);
  }

  done += 1;
  if (done % 50 === 0) log.info(`  ${done}/${list.length} inspected`);
  return result;
});

const ok = results.filter((r) => r.ok);
const summary = {
  total: list.length,
  invalidInput: results.length - ok.length,
  resolving: ok.filter((r) => r.resolves).length,
  withMx: ok.filter((r) => r.hasMx).length,
  withSpf: ok.filter((r) => r.spf).length,
  withDmarc: ok.filter((r) => r.hasDmarc).length,
  sslExpiringIn30Days: ok.filter((r) => r.sslDaysRemaining !== null && r.sslDaysRemaining >= 0 && r.sslDaysRemaining <= 30).length,
  sslExpired: ok.filter((r) => r.sslExpired === true).length,
  finishedAt: new Date().toISOString(),
};

log.info(
  `Done. ${summary.resolving}/${summary.total} resolving | ${summary.withMx} with MX | ` +
    `${summary.withSpf} SPF | ${summary.withDmarc} DMARC | ${summary.sslExpiringIn30Days} SSL expiring <30d | ${summary.sslExpired} SSL expired`,
);

await Actor.setValue('SUMMARY', summary);
await Actor.exit();
