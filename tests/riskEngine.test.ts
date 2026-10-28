import { describe, it, expect } from 'vitest';
import { evaluateWebsiteRisk } from '../src/lib/engine/riskEngine';
import { NormalizedUrlResult } from '../src/lib/normalizer/urlNormalizer';
import { DnsServiceResult } from '../src/lib/services/dnsService';
import { TlsCheckResult } from '../src/lib/services/tlsService';
import { SafeFetchResult } from '../src/lib/fetcher/safeFetch';
import { RdapResult } from '../src/lib/services/rdapService';
import { ContentDetails } from '../src/types/analyzer';

function createMockParams(overrides: Partial<{
  normalized: Partial<NormalizedUrlResult>;
  dns: Partial<DnsServiceResult>;
  tls: Partial<TlsCheckResult>;
  fetch: Partial<SafeFetchResult>;
  rdap: Partial<RdapResult>;
  content: Partial<ContentDetails>;
}>) {
  const normalized: NormalizedUrlResult = {
    isValid: true,
    originalInput: 'https://legit-shop.com',
    normalizedUrl: 'https://legit-shop.com/',
    protocol: 'https:',
    hostname: 'legit-shop.com',
    port: '',
    pathname: '/',
    search: '',
    hash: '',
    registrableDomain: 'legit-shop.com',
    subdomains: [],
    isIpAddress: false,
    isPunycode: false,
    unicodeHostname: 'legit-shop.com',
    hasUserInfo: false,
    isShortener: false,
    suspiciousKeywords: [],
    hyphenCount: 0,
    ...overrides.normalized
  };

  const dns: DnsServiceResult = {
    hasDns: true,
    aRecords: ['93.184.216.34'],
    aaaaRecords: [],
    mxRecords: ['mail.legit-shop.com (priority 10)'],
    txtRecords: [],
    hasMxRecords: true,
    ...overrides.dns
  };

  const tls: TlsCheckResult = {
    tlsAvailable: true,
    tlsValid: true,
    issuer: 'DigiCert Global Root G2',
    subject: 'legit-shop.com',
    validFrom: '2025-01-01',
    validTo: '2027-01-01',
    daysRemaining: 400,
    hostnameMismatch: false,
    authorizationError: null,
    sanList: ['legit-shop.com', 'www.legit-shop.com'],
    ...overrides.tls
  };

  const fetch: SafeFetchResult = {
    accessible: true,
    statusCode: 200,
    statusText: 'OK',
    finalUrl: 'https://legit-shop.com/',
    finalDomain: 'legit-shop.com',
    redirects: [],
    redirectCount: 0,
    domainChangedOnRedirect: false,
    html: '<html>...</html>',
    headers: {},
    htmlSizeBytes: 45000,
    fetchError: null,
    ...overrides.fetch
  };

  const rdap: RdapResult = {
    status: 'verified',
    registrationDate: '2020-03-15T00:00:00Z',
    domainAgeDays: 1400,
    registrar: 'NameCheap, Inc.',
    details: 'Domain registered 1400 days ago.',
    ...overrides.rdap
  };

  const content: ContentDetails = {
    accessible: true,
    statusCode: 200,
    statusText: 'OK',
    title: 'Legit Shop Official',
    metaDescription: 'Official store',
    policies: {
      hasRefundPolicy: true,
      refundPolicyUrl: 'https://legit-shop.com/refunds',
      hasPrivacyPolicy: true,
      privacyPolicyUrl: 'https://legit-shop.com/privacy',
      hasTermsOfService: true,
      termsOfServiceUrl: 'https://legit-shop.com/terms',
      hasShippingPolicy: true,
      shippingPolicyUrl: 'https://legit-shop.com/shipping',
      hasAboutPage: true,
      aboutPageUrl: 'https://legit-shop.com/about'
    },
    contact: {
      emails: ['support@legit-shop.com'],
      phones: ['+1-800-555-0199'],
      hasPhysicalAddress: true,
      addressHints: ['123 Main St, New York, NY'],
      contactPageUrl: 'https://legit-shop.com/contact'
    },
    shopping: {
      hasCartOrCheckout: true,
      hasProductCatalog: true,
      detectedPaymentMethods: ['Visa', 'Mastercard', 'PayPal'],
      suspiciousPaymentRequests: [],
      excessiveDiscountClaims: [],
      urgencyTactics: [],
      socialLinks: ['facebook.com', 'instagram.com']
    },
    htmlSizeBytes: 45000,
    fetchError: null,
    ...overrides.content
  };

  const reputation = {
    googleSafeBrowsing: {
      available: false,
      flagged: false,
      summary: 'Not configured'
    },
    virusTotal: {
      available: false,
      flagged: false,
      summary: 'Not configured'
    }
  };

  return {
    normalized,
    dns,
    tls,
    fetch,
    rdap,
    content,
    reputation,
    timingMs: 250
  };
}

describe('Risk & Confidence Engine', () => {
  it('evaluates legitimate merchant as LOW_RISK with high confidence', () => {
    const params = createMockParams({});
    const res = evaluateWebsiteRisk(params);

    expect(res.riskLevel).toBe('LOW_RISK');
    expect(res.confidence).toBe('high');
    expect(res.signals.some(s => s.id === 'domain_age_established')).toBe(true);
    expect(res.signals.some(s => s.id === 'connection_https_valid')).toBe(true);
    expect(res.signals.some(s => s.id === 'website_refund_policy_found')).toBe(true);
  });

  it('evaluates new domain with missing return policy as MODERATE_RISK', () => {
    const params = createMockParams({
      rdap: {
        status: 'verified',
        registrationDate: new Date(Date.now() - 50 * 86400000).toISOString(),
        domainAgeDays: 50,
        registrar: 'GoDaddy',
        details: 'Domain is 50 days old'
      },
      content: {
        accessible: true,
        statusCode: 200,
        statusText: 'OK',
        title: 'New Store',
        metaDescription: '',
        policies: {
          hasRefundPolicy: false,
          refundPolicyUrl: null,
          hasPrivacyPolicy: true,
          privacyPolicyUrl: 'https://newstore.com/privacy',
          hasTermsOfService: true,
          termsOfServiceUrl: 'https://newstore.com/terms',
          hasShippingPolicy: true,
          shippingPolicyUrl: 'https://newstore.com/shipping',
          hasAboutPage: true,
          aboutPageUrl: 'https://newstore.com/about'
        },
        contact: {
          emails: ['hello@newstore.com'],
          phones: [],
          hasPhysicalAddress: false,
          addressHints: [],
          contactPageUrl: null
        },
        shopping: {
          hasCartOrCheckout: true,
          hasProductCatalog: true,
          detectedPaymentMethods: ['Stripe'],
          suspiciousPaymentRequests: [],
          excessiveDiscountClaims: [],
          urgencyTactics: [],
          socialLinks: []
        },
        htmlSizeBytes: 20000,
        fetchError: null
      }
    });

    const res = evaluateWebsiteRisk(params);
    expect(res.riskLevel).toBe('MODERATE_RISK');
    expect(res.recommendations.some(r => r.includes('caution'))).toBe(true);
  });

  it('evaluates high-risk combination: newly registered + no contact + extreme discounts + redirect', () => {
    const params = createMockParams({
      rdap: {
        status: 'verified',
        registrationDate: new Date(Date.now() - 10 * 86400000).toISOString(),
        domainAgeDays: 10,
        registrar: 'CheapRegistrar',
        details: '10 days old'
      },
      fetch: {
        accessible: true,
        statusCode: 200,
        statusText: 'OK',
        finalUrl: 'https://different-checkout.xyz/pay',
        finalDomain: 'different-checkout.xyz',
        redirects: [{ url: 'https://legit-shop.com', status: 302, domain: 'legit-shop.com' }],
        redirectCount: 1,
        domainChangedOnRedirect: true,
        html: '<html>...</html>',
        headers: {},
        htmlSizeBytes: 12000,
        fetchError: null
      },
      content: {
        accessible: true,
        statusCode: 200,
        statusText: 'OK',
        title: 'Discount Store',
        metaDescription: '',
        policies: {
          hasRefundPolicy: false,
          refundPolicyUrl: null,
          hasPrivacyPolicy: false,
          privacyPolicyUrl: null,
          hasTermsOfService: false,
          termsOfServiceUrl: null,
          hasShippingPolicy: false,
          shippingPolicyUrl: null,
          hasAboutPage: false,
          aboutPageUrl: null
        },
        contact: {
          emails: [],
          phones: [],
          hasPhysicalAddress: false,
          addressHints: [],
          contactPageUrl: null
        },
        shopping: {
          hasCartOrCheckout: true,
          hasProductCatalog: true,
          detectedPaymentMethods: [],
          suspiciousPaymentRequests: [],
          excessiveDiscountClaims: ['95% off everything today only'],
          urgencyTactics: ['Only 1 left in stock'],
          socialLinks: []
        },
        htmlSizeBytes: 12000,
        fetchError: null
      }
    });

    const res = evaluateWebsiteRisk(params);
    expect(res.riskLevel).toBe('HIGH_RISK');
  });

  it('flags CRITICAL when wire transfer or gift card payment is coerced', () => {
    const params = createMockParams({
      content: {
        accessible: true,
        statusCode: 200,
        statusText: 'OK',
        title: 'Fraud Portal',
        metaDescription: '',
        policies: {
          hasRefundPolicy: false,
          refundPolicyUrl: null,
          hasPrivacyPolicy: false,
          privacyPolicyUrl: null,
          hasTermsOfService: false,
          termsOfServiceUrl: null,
          hasShippingPolicy: false,
          shippingPolicyUrl: null,
          hasAboutPage: false,
          aboutPageUrl: null
        },
        contact: {
          emails: [],
          phones: [],
          hasPhysicalAddress: false,
          addressHints: [],
          contactPageUrl: null
        },
        shopping: {
          hasCartOrCheckout: true,
          hasProductCatalog: true,
          detectedPaymentMethods: [],
          suspiciousPaymentRequests: ['Direct Wire Transfer / Bank Transfer Only'],
          excessiveDiscountClaims: [],
          urgencyTactics: [],
          socialLinks: []
        },
        htmlSizeBytes: 15000,
        fetchError: null
      }
    });

    const res = evaluateWebsiteRisk(params);
    expect(res.riskLevel).toBe('CRITICAL');
  });

  it('marks UNABLE_TO_ASSESS when site cannot be reached or resolved', () => {
    const params = createMockParams({
      dns: {
        hasDns: false,
        aRecords: [],
        aaaaRecords: [],
        mxRecords: [],
        txtRecords: [],
        hasMxRecords: false,
        error: 'ENOTFOUND'
      },
      fetch: {
        accessible: false,
        statusCode: null,
        statusText: null,
        finalUrl: 'https://non-existent-shop-12345.com',
        finalDomain: 'non-existent-shop-12345.com',
        redirects: [],
        redirectCount: 0,
        domainChangedOnRedirect: false,
        html: null,
        headers: {},
        htmlSizeBytes: 0,
        fetchError: 'DNS resolution failed'
      }
    });

    const res = evaluateWebsiteRisk(params);
    expect(res.riskLevel).toBe('UNABLE_TO_ASSESS');
    expect(res.confidence).toBe('low');
  });

  it('does NOT treat unavailable WHOIS / RDAP data as malicious', () => {
    const params = createMockParams({
      rdap: {
        status: 'unavailable',
        registrationDate: null,
        domainAgeDays: null,
        registrar: null,
        details: 'Registry rate limit / unavailable'
      }
    });

    const res = evaluateWebsiteRisk(params);
    // Site is otherwise completely legitimate, so missing RDAP does not make it High Risk
    expect(res.riskLevel).toBe('LOW_RISK');
    const rdapSignal = res.signals.find(s => s.id === 'domain_age_unavailable');
    expect(rdapSignal).toBeDefined();
    expect(rdapSignal?.status).toBe('unavailable');
    expect(rdapSignal?.severity).toBe('info');
  });
});
