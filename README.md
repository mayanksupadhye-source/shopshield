# ShopShield

> **Website Risk & Online Shopping Scam Intelligence System**  
> An evidence-first security analysis engine that inspects e-commerce websites and synthesizes real observable network, domain, policy, and payment signals.

---

## Overview

Online shopping fraud rarely looks like generic malware. Fraudulent retail sites frequently feature functional HTTPS encryption, modern responsive design templates, and authentic-looking product photos copied from legitimate retailers. 

**ShopShield** replaces simplistic string heuristics with a comprehensive server-side analysis pipeline. When a user submits an online store URL, ShopShield performs an automated investigation across multiple layers—verifying DNS records, inspecting TLS certificates, tracing redirects, checking ICANN RDAP registration history, parsing HTML content for consumer protection policies, and auditing payment and discount claims.

---

## Core Capabilities

- **Strict SSRF Protection**: Validates every target against private, loopback, link-local, multicast, and reserved IPv4/IPv6 address spaces, both statically and post-DNS resolution.
- **Safe Website Fetching**: Executes controlled HTTP requests with enforced timeouts (7s), strict response size caps (2MB), stream chunk limits, and per-hop SSRF validation across redirects.
- **Domain & RDAP Intelligence**: Directly queries official registry RDAP endpoints for verified registration date and domain age calculation without third-party scraping.
- **TLS Certificate Inspection**: Establishes TLS socket connections to inspect peer certificates, CA issuers, validity dates, days until expiration, and Subject Alternative Name (SAN) hostname matching.
- **Content & Policy Extraction**: Uses static HTML parsing (`cheerio`) to identify refund/return policies, privacy policies, terms of service, shipping terms, customer service emails, telephone numbers, and physical business addresses.
- **Shopping & Payment Risk Detection**: Detects untraceable payment demands (wire transfers, Western Union, crypto-only, gift cards), extreme discount claims (90%+ off everything, blowout liquidation), and artificial urgency countdown timers.
- **Optional Threat Intelligence**: Out-of-the-box support for Google Safe Browsing and VirusTotal APIs with graceful degradation when API keys are not provided.
- **Defensible Risk & Confidence Engine**: Separates **Risk Level** from **Confidence**. Missing data (such as private WHOIS) is marked as `UNAVAILABLE` and is never turned into an artificial penalty.

---

## Risk Classifications

ShopShield classifies analyzed websites into five distinct categories:

| Level | Definition |
| :--- | :--- |
| **LOW RISK** | Standard security baselines are active (valid HTTPS, active MX records, verified refund and contact channels, standard payment methods) with no notable red flags. |
| **MODERATE RISK** | Minor warning signs or missing trust baselines (e.g. recently registered domain, missing return policy, or aggressive promotional claims). Exercise caution. |
| **HIGH RISK** | Multiple compounding risk signals detected (e.g. very newly created domain, cross-domain redirect, absence of verifiable contact details, and extreme discounts). |
| **CRITICAL / STRONG WARNING** | Active threat intelligence match (Google Safe Browsing / VirusTotal) or dangerous untraceable payment coercion (requests for wire transfer, crypto, or gift card codes). |
| **UNABLE TO ASSESS** | The target website could not be accessed, resolved via DNS, or was blocked by security policies. |

---

## Architecture & Tech Stack

```
User Browser (React UI)
        │
        ▼  POST /api/analyze
Next.js App Router (Node.js runtime)
        │
        ├── 1. URL Normalizer (tldts, Punycode, URI sanity)
        ├── 2. SSRF Protection Layer (IPv4/IPv6 private range blocker)
        ├── 3. DNS Service (node:dns A, AAAA, MX, TXT)
        ├── 4. TLS Inspector (node:tls socket certificate validation)
        ├── 5. Safe Fetcher (Redirect chain tracing, timeout, size limits)
        ├── 6. RDAP Service (ICANN standardized domain age)
        ├── 7. Content Analyzer (cheerio static HTML parser)
        ├── 8. Threat Intelligence (Google Safe Browsing, VirusTotal)
        └── 9. Risk & Confidence Synthesis Engine
```

- **Framework**: Next.js 14 (App Router, Node.js Serverless runtime)
- **Language**: TypeScript (Strict mode)
- **HTML Parser**: Cheerio (Static, memory-safe, no JavaScript execution)
- **Domain Extraction**: tldts (Public Suffix List compliant)
- **Testing**: Vitest (50+ unit and integration test cases)
- **Validation**: Zod schema validation

---

## Installation & Setup

### Prerequisites
- Node.js `v18+` (Tested on Node.js `v20` and `v24`)
- npm `v9+`

### 1. Clone the repository
```bash
git clone https://github.com/mayanksupadhye-source/shopshield.git
cd shopshield
```

### 2. Install dependencies
```bash
npm install
```

### 3. Environment configuration
Copy the example environment configuration:
```bash
cp .env.example .env.local
```

Edit `.env.local` to configure optional external reputation APIs:
```env
# Optional External Threat Intelligence APIs
GOOGLE_SAFE_BROWSING_API_KEY=
VIRUSTOTAL_API_KEY=
PORT=3000
```
> **Note**: ShopShield operates fully without these keys. If keys are omitted, reputation checks will cleanly display as `Not Available` without degrading other analysis signals.

---

## Running Locally

### Development mode
```bash
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

### Production build
```bash
npm run build
npm start
```

---

## Running Tests

ShopShield includes an automated test suite covering SSRF defense, URL normalization, HTML content analysis, risk engine classification, and API handlers.

```bash
# Run all tests
npm test
```

---

## API Reference

### Analyze URL
`POST /api/analyze`

**Request:**
```json
{
  "url": "https://example-shop.com"
}
```

**Response:**
```json
{
  "id": "scan_1715000000_abc123",
  "timestamp": "2026-10-29T00:00:00.000Z",
  "originalUrl": "https://example-shop.com",
  "normalizedUrl": "https://example-shop.com/",
  "finalUrl": "https://example-shop.com/",
  "riskLevel": "LOW_RISK",
  "confidence": "high",
  "confidenceReason": "High confidence: Website content, DNS records, TLS certificate, and domain registration data were all successfully verified.",
  "summary": "Low risk: Standard security baselines are in place and no significant scam indicators were observed.",
  "recommendations": [
    "No major red flags were detected during automated inspection.",
    "Remember that basic security measures (like HTTPS or a clean design) do not guarantee business integrity.",
    "Always use credit cards with buyer fraud protection for online shopping."
  ],
  "signals": [
    {
      "id": "connection_https_valid",
      "category": "connection",
      "status": "verified",
      "severity": "info",
      "title": "Valid HTTPS encryption active",
      "evidence": "Encrypted TLS connection verified. Certificate issued by \"DigiCert Global Root G2\"...",
      "confidence": "high",
      "source": "tls_inspector",
      "explanation": "Communication between browser and server is encrypted."
    }
  ],
  "domain": { ... },
  "connection": { ... },
  "content": { ... },
  "reputation": { ... },
  "internalRiskScore": 5,
  "timingMs": 420
}
```

### Health Check
`GET /api/health`

---

## Security Considerations

1. **SSRF Mitigation**: User-supplied URLs are never fetched blindly. Hostnames are resolved to IP addresses and verified against RFC 1918, RFC 3927, RFC 6598, loopback, and multicast networks before initiating HTTP requests.
2. **Redirect Validation**: Redirects are followed with manual loop iteration; every hop is evaluated against the SSRF filter before being fetched.
3. **No Dynamic Execution**: HTML is analyzed statically via Cheerio. User-supplied JavaScript is never executed in Node.js VM or server runtimes.
4. **Credential Safety**: API keys are restricted to server-side environment variables and are never bundled into client payloads.

---

## Honest Limitations

- **HTTPS Does Not Mean Safe**: Free SSL certificates (e.g. Let's Encrypt) are universally available to legitimate merchants and scam operators alike. ShopShield treats HTTPS merely as a transport layer signal, not proof of seller honesty.
- **Professional Appearance Is Easily Cloned**: Modern scraping tools can duplicate complete retail sites in seconds. The presence of a logo or modern CSS does not prove legitimate inventory.
- **Absence of Proof Is Not Proof of Absence**: A website without detected red flags may still be an uncataloged fraudulent storefront. ShopShield provides risk intelligence to assist consumer judgment—not a financial guarantee or legal verdict.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
