import { describe, it, expect } from 'vitest';
import { normalizeUrl } from '../src/lib/normalizer/urlNormalizer';

describe('URL Normalizer', () => {
  it('correctly normalizes standard https URL', () => {
    const res = normalizeUrl('https://example.com');
    expect(res.isValid).toBe(true);
    expect(res.normalizedUrl).toBe('https://example.com/');
    expect(res.hostname).toBe('example.com');
    expect(res.registrableDomain).toBe('example.com');
    expect(res.protocol).toBe('https:');
    expect(res.isIpAddress).toBe(false);
  });

  it('prepends https if protocol is missing', () => {
    const res = normalizeUrl('myshop.store/products?cat=shoes');
    expect(res.isValid).toBe(true);
    expect(res.normalizedUrl).toBe('https://myshop.store/products?cat=shoes');
    expect(res.hostname).toBe('myshop.store');
    expect(res.registrableDomain).toBe('myshop.store');
    expect(res.pathname).toBe('/products');
  });

  it('preserves http when explicitly provided', () => {
    const res = normalizeUrl('http://insecure-shop.com');
    expect(res.isValid).toBe(true);
    expect(res.protocol).toBe('http:');
    expect(res.normalizedUrl).toBe('http://insecure-shop.com/');
  });

  it('cleans markdown link formatting', () => {
    const res = normalizeUrl('[My Shop](https://real-shop.com/deals)');
    expect(res.isValid).toBe(true);
    expect(res.normalizedUrl).toBe('https://real-shop.com/deals');
    expect(res.hostname).toBe('real-shop.com');
  });

  it('detects IP address as host', () => {
    const res = normalizeUrl('http://192.168.1.50/checkout');
    expect(res.isValid).toBe(true);
    expect(res.isIpAddress).toBe(true);
    expect(res.hostname).toBe('192.168.1.50');
  });

  it('detects punycode internationalized domain names', () => {
    const res = normalizeUrl('https://xn--e1afmkfd.xn--p1ai');
    expect(res.isValid).toBe(true);
    expect(res.isPunycode).toBe(true);
    expect(res.unicodeHostname).toBeTruthy();
  });

  it('flags deceptive userinfo (@ symbol in authority)', () => {
    const res = normalizeUrl('https://legit-brand.com@evil-phish.com/store');
    expect(res.isValid).toBe(true);
    expect(res.hasUserInfo).toBe(true);
    expect(res.hostname).toBe('evil-phish.com');
  });

  it('detects known link shorteners', () => {
    const res = normalizeUrl('https://bit.ly/3xSpecialDeal');
    expect(res.isValid).toBe(true);
    expect(res.isShortener).toBe(true);
  });

  it('extracts suspicious lure keywords', () => {
    const res = normalizeUrl('https://mega-deal.com/claim-prize-free-gift');
    expect(res.isValid).toBe(true);
    expect(res.suspiciousKeywords).toContain('free-gift');
    expect(res.suspiciousKeywords).toContain('claim-prize');
  });

  it('detects excessive subdomains', () => {
    const res = normalizeUrl('https://a.b.c.d.shop.com');
    expect(res.isValid).toBe(true);
    expect(res.subdomains.length).toBeGreaterThanOrEqual(3);
  });

  it('rejects unsupported protocols', () => {
    const res = normalizeUrl('ftp://files.example.com');
    expect(res.isValid).toBe(false);
    expect(res.error).toContain('Unsupported protocol');
  });

  it('rejects empty or malformed strings', () => {
    expect(normalizeUrl('').isValid).toBe(false);
    expect(normalizeUrl('    ').isValid).toBe(false);
    expect(normalizeUrl('not-a-url::::').isValid).toBe(false);
  });
});
