import { describe, it, expect } from 'vitest';
import { POST as analyzePost, GET as analyzeGet } from '../src/app/api/analyze/route';
import { GET as healthGet } from '../src/app/api/health/route';
import { NextRequest } from 'next/server';

function createMockRequest(url: string, method: string = 'POST', body?: unknown) {
  const init: RequestInit = {
    method,
    headers: { 'Content-Type': 'application/json' }
  };
  if (body !== undefined) {
    init.body = typeof body === 'string' ? body : JSON.stringify(body);
  }
  return new NextRequest(new URL(url, 'http://localhost:3000'), init);
}

describe('API Route Handlers', () => {
  describe('GET /api/health', () => {
    it('returns service status and capabilities', async () => {
      const response = await healthGet();
      expect(response.status).toBe(200);
      const json = await response.json();
      expect(json.status).toBe('ok');
      expect(json.capabilities).toContain('ssrf_protection');
      expect(json.capabilities).toContain('dns_records');
      expect(json.capabilities).toContain('rdap_whois_lookup');
    });
  });

  describe('GET /api/analyze', () => {
    it('returns endpoint usage information', async () => {
      const response = await analyzeGet();
      expect(response.status).toBe(200);
      const json = await response.json();
      expect(json.service).toContain('ShopShield');
      expect(json.endpoint).toBe('POST /api/analyze');
    });
  });

  describe('POST /api/analyze validation & security', () => {
    it('rejects missing or empty url parameter', async () => {
      const req = createMockRequest('http://localhost:3000/api/analyze', 'POST', { url: '' });
      const res = await analyzePost(req);
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.code).toBe('VALIDATION_ERROR');
    });

    it('rejects invalid JSON body', async () => {
      const req = createMockRequest('http://localhost:3000/api/analyze', 'POST', 'not json');
      const res = await analyzePost(req);
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.code).toBe('INVALID_JSON');
    });

    it('rejects SSRF target: localhost', async () => {
      const req = createMockRequest('http://localhost:3000/api/analyze', 'POST', {
        url: 'http://localhost:8080/admin'
      });
      const res = await analyzePost(req);
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.code).toBe('SSRF_RESTRICTION');
      expect(json.recommendation).toContain('public');
    });

    it('rejects SSRF target: private IP 192.168.1.1', async () => {
      const req = createMockRequest('http://localhost:3000/api/analyze', 'POST', {
        url: 'http://192.168.1.1/setup'
      });
      const res = await analyzePost(req);
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.code).toBe('SSRF_RESTRICTION');
    });

    it('rejects SSRF target: cloud metadata 169.254.169.254', async () => {
      const req = createMockRequest('http://localhost:3000/api/analyze', 'POST', {
        url: 'http://169.254.169.254/latest/meta-data'
      });
      const res = await analyzePost(req);
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.code).toBe('SSRF_RESTRICTION');
    });

    it('rejects malformed URL', async () => {
      const req = createMockRequest('http://localhost:3000/api/analyze', 'POST', {
        url: 'htp:/not a url'
      });
      const res = await analyzePost(req);
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.code).toBe('MALFORMED_URL');
    });
  });
});
