import { normalizeUrl } from './normalizer/urlNormalizer';
import { validateUrlForSsrf } from './security/ssrf';
import { lookupDnsRecords } from './services/dnsService';
import { checkTlsCertificate } from './services/tlsService';
import { safeFetchWebsite } from './fetcher/safeFetch';
import { lookupDomainRdap } from './services/rdapService';
import { analyzeHtmlContent } from './services/contentAnalyzer';
import { checkReputationApis } from './services/reputationService';
import { evaluateWebsiteRisk } from './engine/riskEngine';
import { AnalysisResult } from '../types/analyzer';

export interface PipelineOptions {
  timeoutMs?: number;
}

export async function analyzeWebsiteUrl(
  inputUrl: string,
  options: PipelineOptions = {}
): Promise<AnalysisResult> {
  const startTime = Date.now();
  const normalized = normalizeUrl(inputUrl);

  if (!normalized.isValid) {
    throw new Error(normalized.error || 'Invalid URL provided.');
  }

  // Pre-flight SSRF check
  const ssrf = await validateUrlForSsrf(normalized.normalizedUrl);
  if (!ssrf.safe) {
    throw new Error(`Security validation failed: ${ssrf.reason || 'Restricted network target'}`);
  }

  // Execute external investigations concurrently with individual fault tolerance
  const [dnsResult, tlsResult, fetchResult, rdapResult, reputationResult] = await Promise.all([
    lookupDnsRecords(normalized.hostname).catch(err => ({
      hasDns: false,
      aRecords: [],
      aaaaRecords: [],
      mxRecords: [],
      txtRecords: [],
      hasMxRecords: false,
      error: (err as Error).message
    })),

    (normalized.protocol === 'https:'
      ? checkTlsCertificate(normalized.hostname, normalized.port ? Number.parseInt(normalized.port, 10) : 443)
      : Promise.resolve({
          tlsAvailable: false,
          tlsValid: null,
          issuer: null,
          subject: null,
          validFrom: null,
          validTo: null,
          daysRemaining: null,
          hostnameMismatch: false,
          authorizationError: null,
          sanList: []
        })
    ).catch(err => ({
      tlsAvailable: false,
      tlsValid: null,
      issuer: null,
      subject: null,
      validFrom: null,
      validTo: null,
      daysRemaining: null,
      hostnameMismatch: false,
      authorizationError: (err as Error).message,
      sanList: []
    })),

    safeFetchWebsite(normalized.normalizedUrl, options.timeoutMs).catch(err => ({
      accessible: false,
      statusCode: null,
      statusText: null,
      finalUrl: normalized.normalizedUrl,
      finalDomain: normalized.registrableDomain,
      redirects: [],
      redirectCount: 0,
      domainChangedOnRedirect: false,
      html: null,
      headers: {},
      htmlSizeBytes: 0,
      fetchError: (err as Error).message
    })),

    lookupDomainRdap(normalized.registrableDomain).catch(() => ({
      status: 'unavailable' as const,
      registrationDate: null,
      domainAgeDays: null,
      registrar: null,
      details: 'Domain registration info unavailable.'
    })),

    checkReputationApis(normalized.normalizedUrl).catch(() => ({
      googleSafeBrowsing: {
        available: false,
        flagged: false,
        summary: 'Reputation query failed.'
      },
      virusTotal: {
        available: false,
        flagged: false,
        summary: 'Reputation query failed.'
      }
    }))
  ]);

  // Content analysis from fetched HTML
  const content = analyzeHtmlContent(
    fetchResult.html,
    fetchResult.finalUrl,
    fetchResult.statusCode,
    fetchResult.fetchError
  );

  const durationMs = Date.now() - startTime;

  return evaluateWebsiteRisk({
    normalized,
    dns: dnsResult,
    tls: tlsResult,
    fetch: fetchResult,
    rdap: rdapResult,
    content,
    reputation: reputationResult,
    timingMs: durationMs
  });
}
