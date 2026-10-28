import {
  AnalysisResult,
  AnalysisSignal,
  ConfidenceLevel,
  RiskLevel,
  DomainDetails,
  ConnectionDetails,
  ContentDetails,
  ReputationDetails
} from '../../types/analyzer';
import { NormalizedUrlResult } from '../normalizer/urlNormalizer';
import { DnsServiceResult } from '../services/dnsService';
import { TlsCheckResult } from '../services/tlsService';
import { SafeFetchResult } from '../fetcher/safeFetch';
import { RdapResult } from '../services/rdapService';

export interface EvaluateRiskParams {
  normalized: NormalizedUrlResult;
  dns: DnsServiceResult;
  tls: TlsCheckResult;
  fetch: SafeFetchResult;
  rdap: RdapResult;
  content: ContentDetails;
  reputation: ReputationDetails;
  timingMs: number;
}

export function evaluateWebsiteRisk(params: EvaluateRiskParams): AnalysisResult {
  const { normalized, dns, tls, fetch, rdap, content, reputation, timingMs } = params;
  const signals: AnalysisSignal[] = [];

  // ==========================================
  // 1. DOMAIN SIGNALS
  // ==========================================

  // IP Host
  if (normalized.isIpAddress) {
    signals.push({
      id: 'domain_ip_host',
      category: 'domain',
      status: 'warning',
      severity: 'high',
      title: 'Host is an IP address',
      evidence: `Website URL uses raw IP host "${normalized.hostname}" instead of a registered domain name.`,
      confidence: 'high',
      source: 'domain_normalizer',
      explanation: 'Legitimate shopping retailers operate on branded domain names. Direct IP addresses are frequently used in fly-by-night scam operations.'
    });
  }

  // Punycode / IDN Homograph
  if (normalized.isPunycode) {
    signals.push({
      id: 'domain_punycode',
      category: 'domain',
      status: 'warning',
      severity: 'high',
      title: 'Punycode / Internationalized Domain Name',
      evidence: `Hostname uses Punycode encoding: "${normalized.hostname}" (Decodes to: "${normalized.unicodeHostname}").`,
      confidence: 'high',
      source: 'domain_normalizer',
      explanation: 'Punycode is often used in homograph attacks to impersonate well-known brands using lookalike characters from other alphabets.'
    });
  }

  // Suspicious keywords in URL
  if (normalized.suspiciousKeywords.length > 0) {
    signals.push({
      id: 'domain_suspicious_keywords',
      category: 'domain',
      status: 'warning',
      severity: 'medium',
      title: 'Suspicious keywords in URL structure',
      evidence: `URL contains lure keywords: ${normalized.suspiciousKeywords.map(k => `"${k}"`).join(', ')}.`,
      confidence: 'high',
      source: 'domain_normalizer',
      explanation: 'Phishing and shopping scam websites commonly embed urgent or promotional words directly into their domain or path.'
    });
  }

  // Userinfo in URL (@ symbol in authority)
  if (normalized.hasUserInfo) {
    signals.push({
      id: 'domain_userinfo_auth',
      category: 'domain',
      status: 'critical',
      severity: 'critical',
      title: 'Deceptive @ symbol in URL authority',
      evidence: 'URL contains an @ symbol in the authority component, which masks the real destination host.',
      confidence: 'high',
      source: 'domain_normalizer',
      explanation: 'Browsers treat content before the @ symbol as credentials and navigate to the domain after the @, creating severe deception.'
    });
  }

  // Link shortener
  if (normalized.isShortener) {
    signals.push({
      id: 'domain_shortener',
      category: 'domain',
      status: 'warning',
      severity: 'medium',
      title: 'Link shortening service used',
      evidence: `Domain "${normalized.registrableDomain}" is a known link shortener.`,
      confidence: 'high',
      source: 'domain_normalizer',
      explanation: 'Link shorteners obscure the true destination of an e-commerce website and make pre-click security assessment difficult.'
    });
  }

  // Excessive subdomains
  if (normalized.subdomains.length >= 3) {
    signals.push({
      id: 'domain_excessive_subdomains',
      category: 'domain',
      status: 'warning',
      severity: 'low',
      title: 'Complex subdomain structure',
      evidence: `Domain contains ${normalized.subdomains.length} subdomain levels (${normalized.subdomains.join('.')}).`,
      confidence: 'high',
      source: 'domain_normalizer',
      explanation: 'Deep subdomain nesting can sometimes be used to mimic authentic domains or hide within dynamic hosting providers.'
    });
  }

  // Domain Age (RDAP)
  if (rdap.status === 'verified' && rdap.domainAgeDays !== null) {
    if (rdap.domainAgeDays < 30) {
      signals.push({
        id: 'domain_age_critical_new',
        category: 'domain',
        status: 'warning',
        severity: 'high',
        title: 'Very newly registered domain (< 30 days)',
        evidence: `Domain was created ${rdap.domainAgeDays} day(s) ago (${new Date(rdap.registrationDate!).toLocaleDateString()}) via ${rdap.registrar || 'verified registrar'}.`,
        confidence: 'high',
        source: 'rdap_whois',
        explanation: 'Disposable scam storefronts are typically created days before running deceptive advertising campaigns and abandoned shortly after.'
      });
    } else if (rdap.domainAgeDays < 90) {
      signals.push({
        id: 'domain_age_new',
        category: 'domain',
        status: 'warning',
        severity: 'medium',
        title: 'Recently registered domain (< 90 days)',
        evidence: `Domain is ${rdap.domainAgeDays} days old (${new Date(rdap.registrationDate!).toLocaleDateString()}).`,
        confidence: 'high',
        source: 'rdap_whois',
        explanation: 'Domains under 3 months old have not established a verified operating history and warrant heightened consumer caution.'
      });
    } else {
      signals.push({
        id: 'domain_age_established',
        category: 'domain',
        status: 'verified',
        severity: 'info',
        title: 'Established domain registration',
        evidence: `Domain has been registered for ${Math.floor(rdap.domainAgeDays / 365)} year(s) (${rdap.domainAgeDays} days old, registered ${new Date(rdap.registrationDate!).toLocaleDateString()}).`,
        confidence: 'high',
        source: 'rdap_whois',
        explanation: 'Long-standing domain registration is a positive indicator that the site is not a temporary pop-up scam.'
      });
    }
  } else {
    signals.push({
      id: 'domain_age_unavailable',
      category: 'domain',
      status: 'unavailable',
      severity: 'info',
      title: 'Domain age unavailable',
      evidence: rdap.details,
      confidence: 'medium',
      source: 'rdap_whois',
      explanation: 'Registration age could not be retrieved from the TLD registry. Missing RDAP data is not counted as a risk signal.'
    });
  }

  // DNS & Mail exchange (MX)
  if (dns.hasMxRecords) {
    signals.push({
      id: 'dns_mx_configured',
      category: 'domain',
      status: 'verified',
      severity: 'info',
      title: 'Business email servers (MX) active',
      evidence: `Configured MX records found: ${dns.mxRecords.slice(0, 2).join(', ')}.`,
      confidence: 'high',
      source: 'dns_lookup',
      explanation: 'Active mail exchange records indicate standard organizational email infrastructure.'
    });
  } else if (dns.hasDns) {
    signals.push({
      id: 'dns_no_mx',
      category: 'domain',
      status: 'warning',
      severity: 'low',
      title: 'No email servers (MX) configured',
      evidence: 'Domain has no MX records published in DNS.',
      confidence: 'high',
      source: 'dns_lookup',
      explanation: 'Legitimate shopping retailers usually have business email addresses on their domain. The complete absence of MX records can be an indicator of an incomplete setup.'
    });
  }

  // ==========================================
  // 2. CONNECTION & SECURITY SIGNALS
  // ==========================================

  // HTTPS Usage
  if (normalized.protocol === 'https:') {
    if (tls.tlsAvailable && tls.tlsValid) {
      signals.push({
        id: 'connection_https_valid',
        category: 'connection',
        status: 'verified',
        severity: 'info',
        title: 'Valid HTTPS encryption active',
        evidence: `Encrypted TLS connection verified. Certificate issued by "${tls.issuer || 'Trusted CA'}", valid until ${tls.validTo ? new Date(tls.validTo).toLocaleDateString() : 'N/A'}${tls.daysRemaining ? ` (${tls.daysRemaining} days remaining)` : ''}.`,
        confidence: 'high',
        source: 'tls_inspector',
        explanation: 'Communication between browser and server is encrypted. Note: HTTPS only encrypts transmission; it does not guarantee seller honesty.'
      });
    } else if (tls.tlsAvailable && !tls.tlsValid) {
      signals.push({
        id: 'connection_tls_invalid',
        category: 'connection',
        status: 'warning',
        severity: 'high',
        title: 'Invalid or misconfigured TLS certificate',
        evidence: `TLS handshake issue: ${tls.authorizationError || (tls.hostnameMismatch ? 'Certificate hostname mismatch' : 'Expired or untrusted certificate')}.`,
        confidence: 'high',
        source: 'tls_inspector',
        explanation: 'A broken or mismatched certificate indicates improper server configuration or potential interception.'
      });
    }
  } else {
    signals.push({
      id: 'connection_http_unencrypted',
      category: 'connection',
      status: 'warning',
      severity: 'high',
      title: 'Unencrypted connection (HTTP only)',
      evidence: 'Website does not use HTTPS encryption. All traffic is sent in plaintext.',
      confidence: 'high',
      source: 'protocol_checker',
      explanation: 'Never enter credit cards, passwords, or personal details over unencrypted HTTP.'
    });
  }

  // Redirect Analysis
  if (fetch.domainChangedOnRedirect) {
    signals.push({
      id: 'connection_redirect_domain_switch',
      category: 'connection',
      status: 'warning',
      severity: 'high',
      title: 'Redirected to a different domain',
      evidence: `Submitted URL (${normalized.hostname}) redirected to a completely different domain: "${fetch.finalDomain}".`,
      confidence: 'high',
      source: 'redirect_analyzer',
      explanation: 'Cross-domain redirects are often used to lure users with recognizable names and then push them to unverified checkout domains.'
    });
  } else if (fetch.redirectCount > 2) {
    signals.push({
      id: 'connection_multiple_redirects',
      category: 'connection',
      status: 'warning',
      severity: 'low',
      title: 'Multiple redirect hops detected',
      evidence: `Followed ${fetch.redirectCount} redirects before reaching final destination.`,
      confidence: 'high',
      source: 'redirect_analyzer',
      explanation: 'Excessive redirect chains can be a tactic to bypass automated scanners or cloak content.'
    });
  }

  // ==========================================
  // 3. WEBSITE & CONTENT SIGNALS
  // ==========================================

  if (!fetch.accessible) {
    signals.push({
      id: 'website_inaccessible',
      category: 'website',
      status: 'warning',
      severity: 'high',
      title: 'Website unreachable or blocked',
      evidence: fetch.fetchError || `HTTP status ${fetch.statusCode || 'failed'}`,
      confidence: 'high',
      source: 'safe_fetcher',
      explanation: 'The server could not be reached or refused connection during automated inspection.'
    });
  } else {
    // Contact Information
    const hasAnyContact = content.contact.emails.length > 0 ||
      content.contact.phones.length > 0 ||
      content.contact.hasPhysicalAddress ||
      content.contact.contactPageUrl !== null;

    if (hasAnyContact) {
      const items: string[] = [];
      if (content.contact.emails.length > 0) items.push(`Email (${content.contact.emails[0]})`);
      if (content.contact.phones.length > 0) items.push(`Phone (${content.contact.phones[0]})`);
      if (content.contact.hasPhysicalAddress) items.push('Physical address');
      if (content.contact.contactPageUrl) items.push('Contact page');

      signals.push({
        id: 'website_contact_found',
        category: 'website',
        status: 'verified',
        severity: 'info',
        title: 'Customer contact channels detected',
        evidence: `Identified contact details: ${items.join(', ')}.`,
        confidence: 'high',
        source: 'html_content_parser',
        explanation: 'Legitimate stores provide clear channels for customer support inquiries.'
      });
    } else {
      signals.push({
        id: 'website_no_contact',
        category: 'website',
        status: 'warning',
        severity: 'medium',
        title: 'No business contact details detected',
        evidence: 'No customer service email, telephone number, or physical street address was found in page content.',
        confidence: 'medium',
        source: 'html_content_parser',
        explanation: 'Scam shops often deliberately omit authentic contact information to prevent buyers from reaching them after purchase.'
      });
    }

    // Refund Policy
    if (content.policies.hasRefundPolicy) {
      signals.push({
        id: 'website_refund_policy_found',
        category: 'website',
        status: 'verified',
        severity: 'info',
        title: 'Refund / Return policy page detected',
        evidence: `Found return policy link (${content.policies.refundPolicyUrl || 'page link'}).`,
        confidence: 'high',
        source: 'html_content_parser',
        explanation: 'E-commerce consumer protection laws require clear return and refund guidelines.'
      });
    } else {
      signals.push({
        id: 'website_no_refund_policy',
        category: 'website',
        status: 'warning',
        severity: 'medium',
        title: 'No return/refund policy detected',
        evidence: 'No dedicated refund, return, or cancellation policy link was located on the site.',
        confidence: 'medium',
        source: 'html_content_parser',
        explanation: 'Trustworthy online merchants clearly outline refund and dispute terms. Absence of return terms is a consumer risk factor.'
      });
    }

    // Privacy & Terms
    if (content.policies.hasPrivacyPolicy && content.policies.hasTermsOfService) {
      signals.push({
        id: 'website_legal_policies_found',
        category: 'website',
        status: 'verified',
        severity: 'info',
        title: 'Legal policies (Privacy & Terms) present',
        evidence: 'Both Privacy Policy and Terms of Service agreements were detected.',
        confidence: 'high',
        source: 'html_content_parser',
        explanation: 'Standard legal documentation shows basic compliance with consumer privacy regulations.'
      });
    } else if (!content.policies.hasPrivacyPolicy && !content.policies.hasTermsOfService) {
      signals.push({
        id: 'website_legal_policies_missing',
        category: 'website',
        status: 'warning',
        severity: 'low',
        title: 'Standard legal policies not found',
        evidence: 'Neither Privacy Policy nor Terms of Service links were detected.',
        confidence: 'medium',
        source: 'html_content_parser',
        explanation: 'Professional retail businesses normally present terms of sale and privacy practices.'
      });
    }

    // ==========================================
    // 4. SHOPPING & PAYMENT SIGNALS
    // ==========================================

    // Suspicious Payment Methods (Critical)
    if (content.shopping.suspiciousPaymentRequests.length > 0) {
      signals.push({
        id: 'shopping_suspicious_payment',
        category: 'shopping',
        status: 'critical',
        severity: 'critical',
        title: 'Untraceable / High-risk payment method requested',
        evidence: `Website prompts for: ${content.shopping.suspiciousPaymentRequests.join('; ')}.`,
        confidence: 'high',
        source: 'html_content_parser',
        explanation: 'Requests for wire transfers, gift cards, Zelle, or crypto are a premier indicator of retail fraud, as these transactions cannot be reversed or protected by chargebacks.'
      });
    }

    // Known Payment Providers
    if (content.shopping.detectedPaymentMethods.length > 0) {
      signals.push({
        id: 'shopping_payment_providers',
        category: 'shopping',
        status: 'verified',
        severity: 'info',
        title: 'Recognized payment gateways referenced',
        evidence: `Found references to: ${content.shopping.detectedPaymentMethods.join(', ')}.`,
        confidence: 'high',
        source: 'html_content_parser',
        explanation: 'Mention of credit card networks or PayPal offers potential payment protection mechanisms if actually implemented at checkout.'
      });
    }

    // Extreme discount claims
    if (content.shopping.excessiveDiscountClaims.length > 0) {
      signals.push({
        id: 'shopping_excessive_discounts',
        category: 'shopping',
        status: 'warning',
        severity: 'high',
        title: 'Unrealistic discount claims detected',
        evidence: `Found aggressive discount language: ${content.shopping.excessiveDiscountClaims.map(d => `"${d}"`).join(', ')}.`,
        confidence: 'high',
        source: 'html_content_parser',
        explanation: 'Discounts exceeding 80-90% storewide or "blowout clearance" on brand-name goods are standard lures used by counterfeiters and non-delivery scams.'
      });
    }

    // Urgency / Pressure tactics
    if (content.shopping.urgencyTactics.length > 0) {
      signals.push({
        id: 'shopping_urgency_tactics',
        category: 'shopping',
        status: 'warning',
        severity: 'low',
        title: 'Artificial urgency or pressure tactics',
        evidence: `Pressure tactics detected: ${content.shopping.urgencyTactics.map(u => `"${u}"`).join(', ')}.`,
        confidence: 'high',
        source: 'html_content_parser',
        explanation: 'Artificial countdowns and low-stock claims create panic buying before consumers have time to research the retailer.'
      });
    }
  }

  // ==========================================
  // 5. REPUTATION SIGNALS
  // ==========================================

  // Google Safe Browsing
  if (reputation.googleSafeBrowsing.available) {
    if (reputation.googleSafeBrowsing.flagged) {
      signals.push({
        id: 'reputation_google_safe_browsing_flagged',
        category: 'reputation',
        status: 'critical',
        severity: 'critical',
        title: 'Flagged by Google Safe Browsing',
        evidence: reputation.googleSafeBrowsing.summary,
        confidence: 'high',
        source: 'google_safe_browsing',
        explanation: 'Google Safe Browsing has confirmed this domain is associated with malware, social engineering, or harmful software.'
      });
    } else {
      signals.push({
        id: 'reputation_google_safe_browsing_clean',
        category: 'reputation',
        status: 'verified',
        severity: 'info',
        title: 'Google Safe Browsing: No known threats',
        evidence: reputation.googleSafeBrowsing.summary,
        confidence: 'high',
        source: 'google_safe_browsing',
        explanation: 'Domain is not currently listed on Google Safe Browsing blacklist.'
      });
    }
  } else {
    signals.push({
      id: 'reputation_google_safe_browsing_unavailable',
      category: 'reputation',
      status: 'unavailable',
      severity: 'info',
      title: 'Google Safe Browsing check unavailable',
      evidence: reputation.googleSafeBrowsing.summary,
      confidence: 'low',
      source: 'google_safe_browsing',
      explanation: 'API key not configured in environment. Check omitted without penalty.'
    });
  }

  // VirusTotal
  if (reputation.virusTotal.available) {
    if (reputation.virusTotal.flagged) {
      signals.push({
        id: 'reputation_virustotal_flagged',
        category: 'reputation',
        status: 'critical',
        severity: 'critical',
        title: 'Flagged on VirusTotal security scan',
        evidence: reputation.virusTotal.summary,
        confidence: 'high',
        source: 'virustotal',
        explanation: 'Multiple independent security vendors have flagged this URL as malicious.'
      });
    } else {
      signals.push({
        id: 'reputation_virustotal_clean',
        category: 'reputation',
        status: 'verified',
        severity: 'info',
        title: 'VirusTotal: Clean reputation',
        evidence: reputation.virusTotal.summary,
        confidence: 'high',
        source: 'virustotal',
        explanation: 'Security vendors on VirusTotal report no malicious activity for this URL.'
      });
    }
  } else {
    signals.push({
      id: 'reputation_virustotal_unavailable',
      category: 'reputation',
      status: 'unavailable',
      severity: 'info',
      title: 'VirusTotal check unavailable',
      evidence: reputation.virusTotal.summary,
      confidence: 'low',
      source: 'virustotal',
      explanation: 'VIRUSTOTAL_API_KEY not configured. Check omitted without penalty.'
    });
  }

  // ==========================================
  // 6. SYNTHESIZE RISK LEVEL & CONFIDENCE
  // ==========================================

  const criticalSignals = signals.filter(s => s.severity === 'critical' || s.status === 'critical');
  const highSignals = signals.filter(s => s.severity === 'high' && s.status === 'warning');
  const mediumSignals = signals.filter(s => s.severity === 'medium' && s.status === 'warning');
  const lowSignals = signals.filter(s => s.severity === 'low' && s.status === 'warning');

  let riskLevel: RiskLevel = 'LOW_RISK';

  if (!dns.hasDns && !fetch.accessible) {
    riskLevel = 'UNABLE_TO_ASSESS';
  } else if (criticalSignals.length > 0) {
    riskLevel = 'CRITICAL';
  } else if (highSignals.length >= 2 || (highSignals.length === 1 && mediumSignals.length >= 2)) {
    riskLevel = 'HIGH_RISK';
  } else if (highSignals.length === 1 || mediumSignals.length >= 1 || lowSignals.length >= 2) {
    riskLevel = 'MODERATE_RISK';
  } else {
    riskLevel = 'LOW_RISK';
  }

  // Calculate Data Breadth & Confidence
  let dataPoints = 0;
  if (dns.hasDns) dataPoints++;
  if (fetch.accessible) dataPoints += 2;
  if (tls.tlsAvailable) dataPoints++;
  if (rdap.status === 'verified') dataPoints++;
  if (reputation.googleSafeBrowsing.available || reputation.virusTotal.available) dataPoints++;

  let confidence: ConfidenceLevel = 'medium';
  let confidenceReason = '';

  if (riskLevel === 'UNABLE_TO_ASSESS') {
    confidence = 'low';
    confidenceReason = 'The target website could not be accessed or resolved via DNS to perform substantive inspection.';
  } else if (dataPoints >= 4) {
    confidence = 'high';
    confidenceReason = 'High confidence: Website content, DNS records, TLS certificate, and domain registration data were all successfully verified.';
  } else if (dataPoints >= 2) {
    confidence = 'medium';
    confidenceReason = 'Moderate confidence: Basic network signals and content were analyzed, but some external data (such as WHOIS/RDAP or threat intelligence) was unavailable.';
  } else {
    confidence = 'low';
    confidenceReason = 'Low confidence: Limited data could be gathered for this host.';
  }

  // Internal Risk Score (0-100)
  // Transparent internal indicator for UI visualization only
  let rawScore = 5;
  rawScore += criticalSignals.length * 45;
  rawScore += highSignals.length * 20;
  rawScore += mediumSignals.length * 10;
  rawScore += lowSignals.length * 5;
  if (riskLevel === 'LOW_RISK') rawScore = Math.min(rawScore, 20);
  if (riskLevel === 'MODERATE_RISK') rawScore = Math.min(Math.max(rawScore, 30), 65);
  if (riskLevel === 'HIGH_RISK') rawScore = Math.min(Math.max(rawScore, 70), 88);
  if (riskLevel === 'CRITICAL') rawScore = Math.min(Math.max(rawScore, 92), 100);
  if (riskLevel === 'UNABLE_TO_ASSESS') rawScore = 0;

  // Recommendations
  const recommendations: string[] = [];
  if (riskLevel === 'CRITICAL') {
    recommendations.push('Do NOT enter credit cards, passwords, or personal identity information on this site.');
    recommendations.push('Active threat indicators or coercive untraceable payment demands were detected.');
    recommendations.push('If you already submitted payment details, contact your bank or card issuer immediately to block unauthorized charges.');
  } else if (riskLevel === 'HIGH_RISK') {
    recommendations.push('Exercise extreme caution. Multiple significant risk factors were identified on this site.');
    recommendations.push('Look for independent customer reviews on third-party trust platforms (e.g. Trustpilot, BBB) before buying.');
    recommendations.push('Do not use payment methods that lack fraud chargeback protection (such as wire transfer, gift cards, or crypto).');
  } else if (riskLevel === 'MODERATE_RISK') {
    recommendations.push('Proceed with reasonable caution. Verify the seller’s identity and business credentials before ordering.');
    recommendations.push('Check whether the seller provides active customer service by sending a test inquiry.');
    recommendations.push('Review return, refund, and shipping delivery timetables carefully.');
  } else if (riskLevel === 'UNABLE_TO_ASSESS') {
    recommendations.push('Website could not be reliably inspected. Ensure the URL is typed correctly and the server is online.');
    recommendations.push('Do not proceed with transactions on sites whose identity cannot be verified.');
  } else {
    recommendations.push('No major red flags were detected during automated inspection.');
    recommendations.push('Remember that basic security measures (like HTTPS or a clean design) do not guarantee business integrity.');
    recommendations.push('Always use credit cards with buyer fraud protection for online shopping.');
  }

  // Summary statement
  let summary = '';
  if (riskLevel === 'CRITICAL') {
    const reasons = [...criticalSignals, ...highSignals].map(s => s.title.toLowerCase());
    summary = `Critical warning: Reliable security signals indicate danger. Key findings: ${reasons.slice(0, 3).join(', ')}.`;
  } else if (riskLevel === 'HIGH_RISK') {
    const reasons = [...highSignals, ...mediumSignals].map(s => s.title.toLowerCase());
    summary = `High risk detected: Multiple suspicious indicators were observed (${reasons.slice(0, 3).join(', ')}).`;
  } else if (riskLevel === 'MODERATE_RISK') {
    const reasons = [...highSignals, ...mediumSignals, ...lowSignals].map(s => s.title.toLowerCase());
    summary = `Moderate risk: Some warning signals or missing trust baselines were identified (${reasons.slice(0, 2).join(', ')}).`;
  } else if (riskLevel === 'UNABLE_TO_ASSESS') {
    summary = 'Unable to complete full risk assessment: The website could not be reached, resolved, or analyzed.';
  } else {
    summary = 'Low risk: Standard security baselines are in place and no significant scam indicators were observed.';
  }

  // Compile final structured DomainDetails
  const domainDetails: DomainDetails = {
    hostname: normalized.hostname,
    registrableDomain: normalized.registrableDomain,
    subdomains: normalized.subdomains,
    isIpAddress: normalized.isIpAddress,
    isPunycode: normalized.isPunycode,
    unicodeDomain: normalized.unicodeHostname,
    suspiciousKeywords: normalized.suspiciousKeywords,
    resolvedIps: dns.aRecords.concat(dns.aaaaRecords),
    hasMxRecords: dns.hasMxRecords,
    mxRecords: dns.mxRecords,
    domainAgeDays: rdap.domainAgeDays,
    registrationDate: rdap.registrationDate,
    registrar: rdap.registrar,
    rdapStatus: rdap.status
  };

  // Compile final ConnectionDetails
  const connectionDetails: ConnectionDetails = {
    protocol: normalized.protocol,
    isHttps: normalized.protocol === 'https:',
    tlsAvailable: tls.tlsAvailable,
    tlsValid: tls.tlsValid,
    tlsIssuer: tls.issuer,
    tlsValidFrom: tls.validFrom,
    tlsValidTo: tls.validTo,
    tlsDaysRemaining: tls.daysRemaining,
    tlsHostnameMismatch: tls.hostnameMismatch,
    redirects: fetch.redirects,
    redirectCount: fetch.redirectCount,
    domainChangedOnRedirect: fetch.domainChangedOnRedirect,
    originalDomain: normalized.registrableDomain,
    finalDomain: fetch.finalDomain
  };

  return {
    id: `scan_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`,
    timestamp: new Date().toISOString(),
    originalUrl: normalized.originalInput,
    normalizedUrl: normalized.normalizedUrl,
    finalUrl: fetch.finalUrl,
    riskLevel,
    confidence,
    confidenceReason,
    summary,
    recommendations,
    signals,
    domain: domainDetails,
    connection: connectionDetails,
    content,
    reputation,
    internalRiskScore: rawScore,
    timingMs
  };
}
