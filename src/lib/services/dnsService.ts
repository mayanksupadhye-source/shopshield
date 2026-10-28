import dns from 'node:dns/promises';

export interface DnsServiceResult {
  hasDns: boolean;
  aRecords: string[];
  aaaaRecords: string[];
  mxRecords: string[];
  txtRecords: string[];
  hasMxRecords: boolean;
  error?: string;
}

export async function lookupDnsRecords(hostname: string): Promise<DnsServiceResult> {
  const result: DnsServiceResult = {
    hasDns: false,
    aRecords: [],
    aaaaRecords: [],
    mxRecords: [],
    txtRecords: [],
    hasMxRecords: false
  };

  try {
    // Resolve A records
    try {
      const a = await dns.resolve4(hostname);
      result.aRecords = a;
    } catch {
      // ignore
    }

    // Resolve AAAA records
    try {
      const aaaa = await dns.resolve6(hostname);
      result.aaaaRecords = aaaa;
    } catch {
      // ignore
    }

    // Resolve MX records
    try {
      const mx = await dns.resolveMx(hostname);
      result.mxRecords = mx
        .sort((a, b) => a.priority - b.priority)
        .map(entry => `${entry.exchange} (priority ${entry.priority})`);
      result.hasMxRecords = result.mxRecords.length > 0;
    } catch {
      // Many subdomains don't have MX, so fallback check registrable domain if needed in engine
    }

    // Resolve TXT records
    try {
      const txt = await dns.resolveTxt(hostname);
      result.txtRecords = txt.map(chunks => chunks.join(''));
    } catch {
      // ignore
    }

    result.hasDns = result.aRecords.length > 0 || result.aaaaRecords.length > 0;
    return result;
  } catch (err: unknown) {
    const error = err as Error;
    result.error = error.message;
    return result;
  }
}
