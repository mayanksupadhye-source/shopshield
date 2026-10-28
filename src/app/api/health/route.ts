import { NextResponse } from 'next/server';

export const dynamic = 'force-dynamic';
export const runtime = 'nodejs';

export async function GET() {
  return NextResponse.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    service: 'ShopShield Website Risk & Scam Intelligence System',
    version: '1.0.0',
    capabilities: [
      'ssrf_protection',
      'url_normalization',
      'dns_records',
      'tls_inspection',
      'redirect_chain_tracing',
      'content_policy_analysis',
      'shopping_indicator_detection',
      'rdap_whois_lookup',
      'threat_reputation_apis'
    ],
    reputationApis: {
      googleSafeBrowsing: Boolean(process.env.GOOGLE_SAFE_BROWSING_API_KEY?.trim()),
      virusTotal: Boolean(process.env.VIRUSTOTAL_API_KEY?.trim())
    }
  });
}
