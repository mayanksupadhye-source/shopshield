import { describe, it, expect } from 'vitest';
import {
  isPrivateIPv4,
  isPrivateIPv6,
  isForbiddenHostname,
  validateUrlForSsrf
} from '../src/lib/security/ssrf';

describe('SSRF Protection & Address Validation', () => {
  describe('IPv4 Private & Reserved Ranges', () => {
    it('blocks loopback (127.0.0.0/8)', () => {
      expect(isPrivateIPv4('127.0.0.1')).toBe(true);
      expect(isPrivateIPv4('127.255.255.255')).toBe(true);
    });

    it('blocks current network / broadcast (0.0.0.0/8)', () => {
      expect(isPrivateIPv4('0.0.0.0')).toBe(true);
      expect(isPrivateIPv4('0.1.2.3')).toBe(true);
    });

    it('blocks private class A (10.0.0.0/8)', () => {
      expect(isPrivateIPv4('10.0.0.1')).toBe(true);
      expect(isPrivateIPv4('10.254.1.10')).toBe(true);
    });

    it('blocks private class B (172.16.0.0/12)', () => {
      expect(isPrivateIPv4('172.16.0.1')).toBe(true);
      expect(isPrivateIPv4('172.24.10.5')).toBe(true);
      expect(isPrivateIPv4('172.31.255.255')).toBe(true);
      // 172.32.0.1 is public
      expect(isPrivateIPv4('172.32.0.1')).toBe(false);
    });

    it('blocks private class C (192.168.0.0/16)', () => {
      expect(isPrivateIPv4('192.168.0.1')).toBe(true);
      expect(isPrivateIPv4('192.168.100.254')).toBe(true);
    });

    it('blocks link-local / cloud metadata (169.254.0.0/16)', () => {
      expect(isPrivateIPv4('169.254.169.254')).toBe(true);
      expect(isPrivateIPv4('169.254.1.1')).toBe(true);
    });

    it('blocks CGNAT (100.64.0.0/10)', () => {
      expect(isPrivateIPv4('100.64.0.1')).toBe(true);
      expect(isPrivateIPv4('100.127.255.254')).toBe(true);
      // 100.128.0.1 is not CGNAT
      expect(isPrivateIPv4('100.128.0.1')).toBe(false);
    });

    it('blocks multicast and reserved (224.0.0.0/4, 240.0.0.0/4)', () => {
      expect(isPrivateIPv4('224.0.0.1')).toBe(true);
      expect(isPrivateIPv4('239.255.255.255')).toBe(true);
      expect(isPrivateIPv4('240.0.0.1')).toBe(true);
      expect(isPrivateIPv4('255.255.255.255')).toBe(true);
    });

    it('permits routable public IPv4 addresses', () => {
      expect(isPrivateIPv4('8.8.8.8')).toBe(false);
      expect(isPrivateIPv4('1.1.1.1')).toBe(false);
      expect(isPrivateIPv4('93.184.216.34')).toBe(false);
    });
  });

  describe('IPv6 Private & Reserved Ranges', () => {
    it('blocks IPv6 loopback and unspecified', () => {
      expect(isPrivateIPv6('::1')).toBe(true);
      expect(isPrivateIPv6('::')).toBe(true);
    });

    it('blocks IPv6 unique local (fc00::/7)', () => {
      expect(isPrivateIPv6('fc00::1')).toBe(true);
      expect(isPrivateIPv6('fd12:3456:789a::1')).toBe(true);
    });

    it('blocks IPv6 link-local (fe80::/10)', () => {
      expect(isPrivateIPv6('fe80::1')).toBe(true);
      expect(isPrivateIPv6('fe90::1234')).toBe(true);
    });

    it('blocks IPv4-mapped loopback', () => {
      expect(isPrivateIPv6('::ffff:127.0.0.1')).toBe(true);
      expect(isPrivateIPv6('::ffff:192.168.1.1')).toBe(true);
    });

    it('permits public IPv6', () => {
      expect(isPrivateIPv6('2606:4700:4700::1111')).toBe(false);
      expect(isPrivateIPv6('2001:4860:4860::8888')).toBe(false);
    });
  });

  describe('Hostname restrictions', () => {
    it('blocks localhost and internal domains', () => {
      expect(isForbiddenHostname('localhost')).toBe(true);
      expect(isForbiddenHostname('my.localhost')).toBe(true);
      expect(isForbiddenHostname('server.local')).toBe(true);
      expect(isForbiddenHostname('database.internal')).toBe(true);
      expect(isForbiddenHostname('gateway.lan')).toBe(true);
      expect(isForbiddenHostname('intranet.corp')).toBe(true);
    });

    it('blocks single-word local network machine names', () => {
      expect(isForbiddenHostname('router')).toBe(true);
      expect(isForbiddenHostname('metadata')).toBe(true);
      expect(isForbiddenHostname('backend')).toBe(true);
    });

    it('permits standard public domains', () => {
      expect(isForbiddenHostname('example.com')).toBe(false);
      expect(isForbiddenHostname('google.com')).toBe(false);
      expect(isForbiddenHostname('store.myshop.co.uk')).toBe(false);
    });
  });

  describe('validateUrlForSsrf end-to-end check', () => {
    it('rejects loopback URL', async () => {
      const res = await validateUrlForSsrf('http://127.0.0.1:8080/admin');
      expect(res.safe).toBe(false);
      expect(res.reason).toContain('private or reserved');
    });

    it('rejects localhost URL', async () => {
      const res = await validateUrlForSsrf('http://localhost:3000');
      expect(res.safe).toBe(false);
      expect(res.reason).toContain('private, local, or non-routable');
    });

    it('rejects AWS/cloud metadata address', async () => {
      const res = await validateUrlForSsrf('http://169.254.169.254/latest/meta-data');
      expect(res.safe).toBe(false);
      expect(res.reason).toContain('private or reserved');
    });

    it('rejects internal network .lan or .local URLs', async () => {
      const res = await validateUrlForSsrf('https://printer.local/settings');
      expect(res.safe).toBe(false);
    });
  });
});
