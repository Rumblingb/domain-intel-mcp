import dns from 'dns';
import tls from 'tls';
import { promisify } from 'util';

const resolveMx = promisify(dns.resolveMx);
const resolveNs = promisify(dns.resolveNs);
const resolveTxt = promisify(dns.resolveTxt);
const resolve4 = promisify(dns.resolve4);
const resolve6 = promisify(dns.resolve6);
const resolveCname = promisify(dns.resolveCname);

const DOMAIN_RE = /^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*\.[a-zA-Z]{2,}$/;

export function normaliseDomain(input) {
  let d = String(input ?? '').trim().toLowerCase();
  if (!d) return { ok: false, reason: 'Empty input' };
  // Accept a full URL and reduce it to its hostname.
  if (d.includes('://')) {
    try {
      d = new URL(d).hostname;
    } catch {
      return { ok: false, reason: 'Malformed URL' };
    }
  }
  d = d.replace(/^www\./, '').replace(/\/.*$/, '').replace(/:\d+$/, '');
  if (!DOMAIN_RE.test(d)) return { ok: false, reason: 'Not a valid domain name' };
  return { ok: true, domain: d };
}

async function settle(promise, fallback = null) {
  try {
    return await promise;
  } catch {
    return fallback;
  }
}

// Some networks (corporate DNS, certain ISPs) time out on TXT while answering A/MX
// fine. DNS-over-HTTPS goes out over 443 and sidesteps that entirely, so it is used
// as a fallback whenever native resolution fails or comes back empty.
export async function dohQuery(name, type, { timeoutMs = 6000 } = {}) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`;
    const res = await fetch(url, { signal: ctl.signal, headers: { accept: 'application/dns-json' } });
    if (!res.ok) return [];
    const j = await res.json();
    return (j.Answer ?? [])
      .filter((ans) => String(ans.name ?? '').replace(/\.$/, '').toLowerCase() === name.toLowerCase())
      .map((ans) => String(ans.data ?? ''));
  } catch {
    return [];
  } finally {
    clearTimeout(timer);
  }
}

// DoH returns TXT strings wrapped in quotes, and splits long records into
// several quoted chunks that must be concatenated.
export function unquoteTxt(raw) {
  const chunks = String(raw).match(/"([^"]*)"/g);
  if (!chunks) return String(raw).replace(/^"|"$/g, '');
  return chunks.map((c) => c.slice(1, -1)).join('');
}

async function txtWithFallback(name) {
  const native = await settle(resolveTxt(name), null);
  if (native && native.length > 0) {
    return native.map((chunks) => (Array.isArray(chunks) ? chunks.join('') : String(chunks)));
  }
  const doh = await dohQuery(name, 'TXT');
  return doh.map(unquoteTxt);
}

export async function dnsRecords(domain) {
  const [a, aaaa, mx, ns, flatTxt, cname] = await Promise.all([
    settle(resolve4(domain), []),
    settle(resolve6(domain), []),
    settle(resolveMx(domain), []),
    settle(resolveNs(domain), []),
    txtWithFallback(domain),
    settle(resolveCname(domain), []),
  ]);

  return {
    a: a ?? [],
    aaaa: aaaa ?? [],
    mx: (mx ?? []).sort((x, y) => x.priority - y.priority).map((r) => `${r.priority} ${r.exchange}`),
    ns: (ns ?? []).sort(),
    txt: flatTxt,
    cname: cname ?? [],
  };
}

// Derived signals buyers actually filter on.
export function mailSignals(records) {
  const txt = records.txt ?? [];
  const spf = txt.find((t) => t.toLowerCase().startsWith('v=spf1')) ?? null;
  const dmarcPresent = null; // resolved separately against _dmarc.<domain>
  const mxHosts = (records.mx ?? []).map((m) => m.split(' ').slice(1).join(' ').toLowerCase());

  let provider = null;
  const joined = mxHosts.join(' ');
  if (/google|googlemail/.test(joined)) provider = 'Google Workspace';
  else if (/outlook|protection\.outlook|microsoft/.test(joined)) provider = 'Microsoft 365';
  else if (/zoho/.test(joined)) provider = 'Zoho';
  else if (/protonmail|proton\.me/.test(joined)) provider = 'Proton';
  else if (/mimecast/.test(joined)) provider = 'Mimecast';
  else if (/barracuda/.test(joined)) provider = 'Barracuda';
  else if (/pphosted|proofpoint/.test(joined)) provider = 'Proofpoint';
  else if (mxHosts.length > 0) provider = 'Other / self-hosted';

  return { hasMx: mxHosts.length > 0, mailProvider: provider, spf, dmarcPresent };
}

export async function dmarcRecord(domain) {
  const flat = await txtWithFallback(`_dmarc.${domain}`);
  return flat.find((t) => t.toLowerCase().startsWith('v=dmarc1')) ?? null;
}

export function sslInfo(domain, { timeoutMs = 8000 } = {}) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (v) => {
      if (!settled) {
        settled = true;
        resolve(v);
      }
    };

    let socket;
    try {
      socket = tls.connect(
        { host: domain, port: 443, servername: domain, rejectUnauthorized: false, timeout: timeoutMs },
        () => {
          const cert = socket.getPeerCertificate(false);
          if (!cert || Object.keys(cert).length === 0) {
            socket.destroy();
            return done({ reachable: true, error: 'No certificate presented' });
          }
          const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
          const validFrom = cert.valid_from ? new Date(cert.valid_from) : null;
          const daysRemaining =
            validTo && !Number.isNaN(validTo.valueOf())
              ? Math.floor((validTo.getTime() - Date.now()) / 86400000)
              : null;

          socket.destroy();
          done({
            reachable: true,
            issuer: cert.issuer?.O ?? cert.issuer?.CN ?? null,
            subject: cert.subject?.CN ?? null,
            altNames: cert.subjectaltname ?? null,
            validFrom: validFrom && !Number.isNaN(validFrom.valueOf()) ? validFrom.toISOString() : null,
            validTo: validTo && !Number.isNaN(validTo.valueOf()) ? validTo.toISOString() : null,
            daysRemaining,
            expired: daysRemaining !== null ? daysRemaining < 0 : null,
            protocol: socket.getProtocol?.() ?? null,
          });
        },
      );
    } catch (err) {
      return done({ reachable: false, error: err.message });
    }

    socket.on('timeout', () => {
      socket.destroy();
      done({ reachable: false, error: `TLS handshake timed out after ${timeoutMs}ms` });
    });
    socket.on('error', (err) => {
      socket.destroy();
      done({ reachable: false, error: err.message });
    });
  });
}

// RDAP is the IETF replacement for WHOIS: free, keyless, JSON, and rate-limit friendly.
export async function rdapLookup(domain, { timeoutMs = 10000 } = {}) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      signal: ctl.signal,
      headers: { accept: 'application/rdap+json' },
    });
    if (res.status === 404) return { found: false };
    if (!res.ok) return { found: false, error: `RDAP returned HTTP ${res.status}` };

    const j = await res.json();
    const events = Object.fromEntries((j.events ?? []).map((e) => [e.eventAction, e.eventDate]));
    const registrarEntity = (j.entities ?? []).find((e) => (e.roles ?? []).includes('registrar'));
    let registrar = registrarEntity?.vcardArray?.[1]?.find?.((f) => f[0] === 'fn')?.[3] ?? null;
    if (!registrar && registrarEntity?.handle) registrar = String(registrarEntity.handle);

    const registered = events.registration ?? null;
    const ageDays = registered ? Math.floor((Date.now() - new Date(registered).getTime()) / 86400000) : null;

    return {
      found: true,
      registrar,
      status: j.status ?? [],
      registered,
      expires: events.expiration ?? null,
      lastChanged: events.lastChanged ?? events['last changed'] ?? null,
      ageDays: Number.isFinite(ageDays) ? ageDays : null,
      nameservers: (j.nameservers ?? []).map((n) => String(n.ldhName ?? '').toLowerCase()).filter(Boolean),
    };
  } catch (err) {
    if (err.name === 'AbortError') return { found: false, error: `RDAP timed out after ${timeoutMs}ms` };
    return { found: false, error: err.message };
  } finally {
    clearTimeout(timer);
  }
}

export async function inspectDomain(raw, opts = {}) {
  const { includeSsl = true, includeRdap = true, sslTimeoutMs = 8000, rdapTimeoutMs = 10000 } = opts;

  const norm = normaliseDomain(raw);
  if (!norm.ok) {
    return { input: String(raw ?? ''), domain: null, ok: false, reason: norm.reason };
  }
  const domain = norm.domain;

  const [records, dmarc, ssl, rdap] = await Promise.all([
    dnsRecords(domain),
    dmarcRecord(domain),
    includeSsl ? sslInfo(domain, { timeoutMs: sslTimeoutMs }) : Promise.resolve(null),
    includeRdap ? rdapLookup(domain, { timeoutMs: rdapTimeoutMs }) : Promise.resolve(null),
  ]);

  const mail = mailSignals(records);
  mail.dmarcPresent = dmarc !== null;

  const resolves = (records.a?.length ?? 0) > 0 || (records.aaaa?.length ?? 0) > 0;

  return {
    input: String(raw ?? ''),
    domain,
    ok: true,
    resolves,
    ipv4: records.a,
    ipv6: records.aaaa,
    nameservers: records.ns,
    mx: records.mx,
    hasMx: mail.hasMx,
    mailProvider: mail.mailProvider,
    spf: mail.spf,
    hasSpf: Boolean(mail.spf),
    dmarc,
    hasDmarc: mail.dmarcPresent,
    txt: records.txt,
    cname: records.cname,
    registrar: rdap?.registrar ?? null,
    registered: rdap?.registered ?? null,
    expires: rdap?.expires ?? null,
    domainAgeDays: rdap?.ageDays ?? null,
    domainStatus: rdap?.status ?? [],
    sslIssuer: ssl?.issuer ?? null,
    sslValidTo: ssl?.validTo ?? null,
    sslDaysRemaining: ssl?.daysRemaining ?? null,
    sslExpired: ssl?.expired ?? null,
    sslReachable: ssl?.reachable ?? null,
    checkedAt: new Date().toISOString(),
  };
}

export async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let i = 0;
  const workers = new Array(Math.min(limit, items.length)).fill(null).map(async () => {
    while (i < items.length) {
      const idx = i++;
      out[idx] = await fn(items[idx], idx);
    }
  });
  await Promise.all(workers);
  return out;
}
