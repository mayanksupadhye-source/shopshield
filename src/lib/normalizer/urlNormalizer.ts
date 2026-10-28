import { parse as parseTld } from 'tldts';
import { domainToUnicode } from 'node:url';

export interface NormalizedUrlResult {
  isValid: boolean;
  error?: string;
  originalInput: string;
  normalizedUrl: string;
  protocol: 'http:' | 'https:';
  hostname: string;
  port: string;
  pathname: string;
  search: string;
  hash: string;
  registrableDomain: string;
  subdomains: string[];
  isIpAddress: boolean;
  isPunycode: boolean;
  unicodeHostname: string;
  hasUserInfo: boolean;
  isShortener: boolean;
  suspiciousKeywords: string[];
  hyphenCount: number;
}

const SUSPICIOUS_KEYWORDS = [
  'scam',
  'fake',
  'free-gift',
  'claim-prize',
  'claim-reward',
  'login-verify',
  'urgent-notice',
  'cheap-deal',
  'mega-discount',
  'clearance-outlet',
  'flash-sale-90',
  'official-stores-cheap',
  'secure-banking-verify',
  'update-billing'
];

const KNOWN_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  'is.gd',
  't.co',
  'cutt.ly',
  'rb.gy',
  'shorturl.at',
  'ow.ly',
  'buff.ly',
  'adf.ly',
  'bl.ink'
]);

/**
 * Normalizes and extracts structured domain and URL metadata from user input.
 */
export function normalizeUrl(rawInput: string): NormalizedUrlResult {
  if (!rawInput || typeof rawInput !== 'string') {
    return {
      isValid: false,
      error: 'Empty or invalid URL provided.',
      originalInput: '',
      normalizedUrl: '',
      protocol: 'https:',
      hostname: '',
      port: '',
      pathname: '',
      search: '',
      hash: '',
      registrableDomain: '',
      subdomains: [],
      isIpAddress: false,
      isPunycode: false,
      unicodeHostname: '',
      hasUserInfo: false,
      isShortener: false,
      suspiciousKeywords: [],
      hyphenCount: 0
    };
  }

  let cleaned = rawInput.trim();

  // Strip Markdown link formatting like [example.com](https://example.com) or <https://...>
  const mdMatch = cleaned.match(/\[.*?\]\((https?:\/\/[^\s)]+)\)/i);
  if (mdMatch) {
    cleaned = mdMatch[1];
  } else {
    cleaned = cleaned.replace(/^<|>$/g, '');
  }

  // If a scheme is already present, do not prepend https://
  const hasScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//i.test(cleaned);
  if (!hasScheme) {
    cleaned = `https://${cleaned}`;
  }

  let parsed: URL;
  try {
    parsed = new URL(cleaned);
  } catch {
    return {
      isValid: false,
      error: 'Malformed website address. Please enter a valid URL, e.g. https://example.com',
      originalInput: rawInput,
      normalizedUrl: '',
      protocol: 'https:',
      hostname: '',
      port: '',
      pathname: '',
      search: '',
      hash: '',
      registrableDomain: '',
      subdomains: [],
      isIpAddress: false,
      isPunycode: false,
      unicodeHostname: '',
      hasUserInfo: false,
      isShortener: false,
      suspiciousKeywords: [],
      hyphenCount: 0
    };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      isValid: false,
      error: `Unsupported protocol "${parsed.protocol}". Only HTTP and HTTPS are permitted for website analysis.`,
      originalInput: rawInput,
      normalizedUrl: parsed.href,
      protocol: 'https:',
      hostname: parsed.hostname || '',
      port: parsed.port || '',
      pathname: parsed.pathname || '/',
      search: parsed.search || '',
      hash: parsed.hash || '',
      registrableDomain: '',
      subdomains: [],
      isIpAddress: false,
      isPunycode: false,
      unicodeHostname: '',
      hasUserInfo: false,
      isShortener: false,
      suspiciousKeywords: [],
      hyphenCount: 0
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const tldInfo = parseTld(hostname);
  const registrableDomain = tldInfo.domain || hostname;
  const isIpAddress = Boolean(tldInfo.isIp);
  const subdomains = tldInfo.subdomain ? tldInfo.subdomain.split('.') : [];

  if (!hostname || (!hostname.includes('.') && !isIpAddress && hostname !== 'localhost')) {
    return {
      isValid: false,
      error: `Invalid domain name "${hostname}". Please enter a valid website address with a domain extension (e.g. example.com).`,
      originalInput: rawInput,
      normalizedUrl: parsed.href,
      protocol: parsed.protocol as 'http:' | 'https:',
      hostname: hostname || '',
      port: parsed.port,
      pathname: parsed.pathname,
      search: parsed.search,
      hash: parsed.hash,
      registrableDomain: '',
      subdomains: [],
      isIpAddress,
      isPunycode: false,
      unicodeHostname: '',
      hasUserInfo: false,
      isShortener: false,
      suspiciousKeywords: [],
      hyphenCount: 0
    };
  }

  // Punycode / IDN
  const isPunycode = hostname.includes('xn--');
  const unicodeHostname = domainToUnicode(hostname);

  // Authority userinfo check (e.g. https://legit.com@phish.com)
  const hasUserInfo = Boolean(parsed.username || parsed.password || rawInput.includes('@'));

  // Shortener check
  const isShortener = KNOWN_SHORTENERS.has(registrableDomain) || KNOWN_SHORTENERS.has(hostname);

  // Keyword check
  const fullTargetString = `${hostname} ${parsed.pathname} ${parsed.search}`.toLowerCase();
  const foundKeywords = SUSPICIOUS_KEYWORDS.filter(kw => fullTargetString.includes(kw));

  // Hyphens in registrable domain
  const domainLabel = registrableDomain.split('.')[0] || '';
  const hyphenCount = (domainLabel.match(/-/g) || []).length;

  return {
    isValid: true,
    originalInput: rawInput,
    normalizedUrl: parsed.href,
    protocol: parsed.protocol as 'http:' | 'https:',
    hostname,
    port: parsed.port,
    pathname: parsed.pathname,
    search: parsed.search,
    hash: parsed.hash,
    registrableDomain,
    subdomains,
    isIpAddress,
    isPunycode,
    unicodeHostname,
    hasUserInfo,
    isShortener,
    suspiciousKeywords: foundKeywords,
    hyphenCount
  };
}
