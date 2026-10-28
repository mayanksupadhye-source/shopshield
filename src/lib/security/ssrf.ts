import dns from 'node:dns/promises';
import net from 'node:net';

/**
 * Checks whether an IPv4 address is within a private, loopback, link-local,
 * carrier-grade NAT, test-net, multicast, or reserved range.
 */
export function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split('.').map(p => Number.parseInt(p, 10));
  if (parts.length !== 4 || parts.some(p => Number.isNaN(p) || p < 0 || p > 255)) {
    return true; // malformed treated as unsafe
  }

  const [a, b] = parts;

  // 0.0.0.0/8 (Current network)
  if (a === 0) return true;

  // 10.0.0.0/8 (Private-Use RFC 1918)
  if (a === 10) return true;

  // 127.0.0.0/8 (Loopback RFC 1122)
  if (a === 127) return true;

  // 100.64.0.0/10 (Shared Address Space / CGNAT RFC 6598)
  if (a === 100 && b >= 64 && b <= 127) return true;

  // 169.254.0.0/16 (Link Local RFC 3927)
  if (a === 169 && b === 254) return true;

  // 172.16.0.0/12 (Private-Use RFC 1918: 172.16.0.0 - 172.31.255.255)
  if (a === 172 && b >= 16 && b <= 31) return true;

  // 192.0.0.0/24 (IETF Protocol Assignments RFC 6890)
  if (a === 192 && b === 0 && parts[2] === 0) return true;

  // 192.0.2.0/24 (TEST-NET-1 RFC 5737)
  if (a === 192 && b === 0 && parts[2] === 2) return true;

  // 192.168.0.0/16 (Private-Use RFC 1918)
  if (a === 192 && b === 168) return true;

  // 198.18.0.0/15 (Benchmarking RFC 2544)
  if (a === 198 && (b === 18 || b === 19)) return true;

  // 198.51.100.0/24 (TEST-NET-2 RFC 5737)
  if (a === 198 && b === 51 && parts[2] === 100) return true;

  // 203.0.113.0/24 (TEST-NET-3 RFC 5737)
  if (a === 203 && b === 0 && parts[2] === 113) return true;

  // 224.0.0.0/4 (Multicast RFC 5771: 224.0.0.0 - 239.255.255.255)
  if (a >= 224 && a <= 239) return true;

  // 240.0.0.0/4 (Reserved for future use RFC 1112: 240.0.0.0 - 255.255.255.254)
  // 255.255.255.255/32 (Broadcast)
  if (a >= 240) return true;

  return false;
}

/**
 * Checks whether an IPv6 address is loopback, unique local (fc00::/7),
 * link-local (fe80::/10), multicast (ff00::/8), or IPv4-mapped (::ffff:0:0/96).
 */
export function isPrivateIPv6(ip: string): boolean {
  const normalized = ip.toLowerCase().trim();

  // Loopback and unspecified
  if (normalized === '::1' || normalized === '::') return true;

  // IPv4-mapped IPv6 (::ffff:127.0.0.1 or ::ffff:7f00:1)
  if (normalized.startsWith('::ffff:')) {
    const v4Part = normalized.replace('::ffff:', '');
    if (net.isIPv4(v4Part)) {
      return isPrivateIPv4(v4Part);
    }
    return true; // Any strange mapped address should be rejected
  }

  // Unique local addresses (fc00::/7 -> starts with fc or fd)
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true;

  // Link-local addresses (fe80::/10 -> starts with fe8, fe9, fea, feb)
  if (/^fe[89ab]/i.test(normalized)) return true;

  // Multicast (ff00::/8)
  if (normalized.startsWith('ff')) return true;

  // Documentation (2001:db8::/32)
  if (normalized.startsWith('2001:db8:')) return true;

  // Discard prefix (100::/64)
  if (normalized.startsWith('100::')) return true;

  return false;
}

/**
 * Validates any IP address string.
 */
export function isPrivateIp(ip: string): boolean {
  const version = net.isIP(ip);
  if (version === 4) return isPrivateIPv4(ip);
  if (version === 6) return isPrivateIPv6(ip);
  return true; // Not an IP or malformed
}

/**
 * Checks if the hostname itself is suspicious / internal.
 */
export function isForbiddenHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().trim();

  // Strip brackets from IPv6 hostnames [::1]
  const cleanHost = host.startsWith('[') && host.endsWith(']')
    ? host.slice(1, -1)
    : host;

  if (net.isIP(cleanHost)) {
    return isPrivateIp(cleanHost);
  }

  if (cleanHost === 'localhost') return true;

  const forbiddenSuffixes = [
    '.localhost',
    '.local',
    '.internal',
    '.lan',
    '.home',
    '.corp',
    '.intranet',
    '.test',
    '.example',
    '.invalid',
    '.onion',
    '.i2p'
  ];

  if (forbiddenSuffixes.some(suffix => cleanHost.endsWith(suffix))) {
    return true;
  }

  // Reject single-word hostnames (e.g., 'router', 'printer', 'metadata')
  if (!cleanHost.includes('.')) {
    return true;
  }

  return false;
}

export interface SsrfCheckResult {
  safe: boolean;
  reason?: string;
  resolvedIps?: string[];
}

/**
 * Validates a target URL against SSRF vulnerabilities by checking:
 * 1. Protocol (must be http: or https:)
 * 2. Hostname restrictions (no localhost, internal TLDs, single labels)
 * 3. DNS resolution of all A and AAAA records, ensuring NO resolved IP
 *    is in a private/reserved/internal IP range.
 */
export async function validateUrlForSsrf(urlStr: string | URL): Promise<SsrfCheckResult> {
  let url: URL;
  try {
    url = typeof urlStr === 'string' ? new URL(urlStr) : urlStr;
  } catch {
    return { safe: false, reason: 'Malformed or unparseable URL.' };
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return {
      safe: false,
      reason: `Unsupported protocol "${url.protocol}". Only HTTP and HTTPS are permitted.`
    };
  }

  const hostname = url.hostname;

  if (!hostname) {
    return { safe: false, reason: 'URL missing hostname.' };
  }

  // If hostname is directly an IP address
  const cleanHost = hostname.startsWith('[') && hostname.endsWith(']')
    ? hostname.slice(1, -1)
    : hostname;

  if (net.isIP(cleanHost)) {
    if (isPrivateIp(cleanHost)) {
      return {
        safe: false,
        reason: `Target IP "${cleanHost}" is in a private or reserved range.`,
        resolvedIps: [cleanHost]
      };
    }
    return { safe: true, resolvedIps: [cleanHost] };
  }

  if (isForbiddenHostname(hostname)) {
    return {
      safe: false,
      reason: `Target hostname "${hostname}" is private, local, or non-routable.`
    };
  }

  // Resolve hostname via DNS to ensure all IPs are public and routable
  try {
    const resolvedIps: string[] = [];

    try {
      const v4 = await dns.resolve4(hostname);
      resolvedIps.push(...v4);
    } catch {
      // It may only have AAAA records or resolve later
    }

    try {
      const v6 = await dns.resolve6(hostname);
      resolvedIps.push(...v6);
    } catch {
      // It may only have A records
    }

    if (resolvedIps.length === 0) {
      // Fallback lookup using dns.lookup
      try {
        const lookupResult = await dns.lookup(hostname, { all: true });
        resolvedIps.push(...lookupResult.map(r => r.address));
      } catch (err: unknown) {
        const error = err as Error;
        return {
          safe: false,
          reason: `DNS lookup failed for hostname "${hostname}": ${error.message || 'Domain does not resolve'}.`
        };
      }
    }

    if (resolvedIps.length === 0) {
      return {
        safe: false,
        reason: `Could not resolve any IP address for host "${hostname}".`
      };
    }

    // Verify each resolved IP
    for (const ip of resolvedIps) {
      if (isPrivateIp(ip)) {
        return {
          safe: false,
          reason: `DNS for "${hostname}" resolved to private or reserved IP address "${ip}".`,
          resolvedIps
        };
      }
    }

    return { safe: true, resolvedIps };
  } catch (err: unknown) {
    const error = err as Error;
    return {
      safe: false,
      reason: `DNS resolution failed for "${hostname}": ${error.message}`
    };
  }
}
