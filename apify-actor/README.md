# Domain Intel — DNS, WHOIS/RDAP, SSL & mail posture

Bulk domain enrichment in one pass: DNS records, registrar and domain age, SSL certificate
expiry, and mail posture (provider, SPF, DMARC).

No API keys. No WHOIS subscription. No per-lookup vendor cost.

## What you get per domain

| Group | Fields |
|---|---|
| **DNS** | `ipv4`, `ipv6`, `mx`, `nameservers`, `txt`, `cname`, `resolves` |
| **Mail** | `mailProvider`, `hasMx`, `spf`, `hasSpf`, `dmarc`, `hasDmarc` |
| **Registration** | `registrar`, `registered`, `expires`, `domainAgeDays`, `domainStatus` |
| **SSL** | `sslIssuer`, `sslValidTo`, `sslDaysRemaining`, `sslExpired`, `sslReachable` |

`mailProvider` is derived from MX records and identifies Google Workspace, Microsoft 365,
Zoho, Proton, Mimecast, Barracuda and Proofpoint, falling back to `Other / self-hosted`.

## Input

```json
{
  "domains": ["stripe.com", "https://www.github.com/features", "example.co.uk"],
  "includeSsl": true,
  "includeRdap": true,
  "maxConcurrency": 8
}
```

Full URLs are accepted and reduced to their hostname; a leading `www.` is stripped. Wire
`domains` to another Actor's output for bulk enrichment.

| Field | Default | Notes |
|---|---|---|
| `domains` | — | Required. |
| `includeSsl` | `true` | TLS handshake on 443 to read the certificate. Adds ~0.3–1s per domain. |
| `includeRdap` | `true` | Registrar and age lookup. Adds ~0.3–1s per domain. |
| `maxConcurrency` | 8 | Keep at or below 10 so RDAP does not rate-limit you. |

## Output

```json
{
  "domain": "stripe.com",
  "resolves": true,
  "ipv4": ["198.202.176.161", "198.137.150.161"],
  "mx": ["10 aspmx.l.google.com", "20 alt1.aspmx.l.google.com"],
  "hasMx": true,
  "mailProvider": "Google Workspace",
  "spf": "v=spf1 ip4:198.2.180.60/32 include:spf1.stripe.com ~all",
  "hasSpf": true,
  "dmarc": "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-reports@stripe.com;",
  "hasDmarc": true,
  "registrar": "SafeNames Ltd.",
  "registered": "1995-09-13T04:00:00Z",
  "domainAgeDays": 11278,
  "sslIssuer": "DigiCert Inc",
  "sslDaysRemaining": 106,
  "sslExpired": false
}
```

A `SUMMARY` record lands in the key-value store with run totals: how many resolve, how many
have MX/SPF/DMARC, and how many certificates are **expired or expiring within 30 days**.

There is a second dataset view, **SSL expiry watch**, that shows just the certificate columns.

## Typical uses

- **Lead qualification** — filter a prospect list to domains that actually resolve and accept mail
- **Email deliverability audits** — find prospects or clients with no SPF or no DMARC, which is a concrete thing to sell them
- **Certificate monitoring** — schedule it and alert on `sslDaysRemaining <= 30`
- **Tech-stack segmentation** — split a list by Google Workspace vs Microsoft 365
- **Domain due diligence** — `domainAgeDays` and `domainStatus` for fraud and acquisition checks

## Reliability note

DNS TXT resolution falls back to **DNS-over-HTTPS** whenever the platform resolver fails or
returns nothing. Some networks answer A and MX queries fine but silently time out on TXT,
which would otherwise make SPF and DMARC look absent when they are published. The fallback
runs over port 443 and sidesteps that entirely.

## Limits

RDAP coverage varies by TLD — a few ccTLDs do not operate an RDAP service, in which case
registrar and age come back `null` while everything else is unaffected. SSL fields require a
reachable host on port 443; `sslReachable: false` records the reason.
