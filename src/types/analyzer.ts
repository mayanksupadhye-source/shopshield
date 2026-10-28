export type RiskLevel =
  | 'LOW_RISK'
  | 'MODERATE_RISK'
  | 'HIGH_RISK'
  | 'CRITICAL'
  | 'UNABLE_TO_ASSESS';

export type ConfidenceLevel = 'low' | 'medium' | 'high';

export type SignalCategory =
  | 'domain'
  | 'connection'
  | 'website'
  | 'shopping'
  | 'reputation';

export type SignalStatus =
  | 'verified'
  | 'warning'
  | 'critical'
  | 'not_detected'
  | 'unavailable'
  | 'neutral';

export type SignalSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface AnalysisSignal {
  id: string;
  category: SignalCategory;
  status: SignalStatus;
  severity: SignalSeverity;
  title: string;
  evidence: string;
  confidence: ConfidenceLevel;
  source: string;
  explanation: string;
}

export interface DomainDetails {
  hostname: string;
  registrableDomain: string;
  subdomains: string[];
  isIpAddress: boolean;
  isPunycode: boolean;
  unicodeDomain: string | null;
  suspiciousKeywords: string[];
  resolvedIps: string[];
  hasMxRecords: boolean;
  mxRecords: string[];
  domainAgeDays: number | null;
  registrationDate: string | null;
  registrar: string | null;
  rdapStatus: 'verified' | 'unavailable' | 'error';
}

export interface RedirectHop {
  url: string;
  status: number;
  domain: string;
}

export interface ConnectionDetails {
  protocol: 'http:' | 'https:';
  isHttps: boolean;
  tlsAvailable: boolean;
  tlsValid: boolean | null;
  tlsIssuer: string | null;
  tlsValidFrom: string | null;
  tlsValidTo: string | null;
  tlsDaysRemaining: number | null;
  tlsHostnameMismatch: boolean;
  redirects: RedirectHop[];
  redirectCount: number;
  domainChangedOnRedirect: boolean;
  originalDomain: string;
  finalDomain: string;
}

export interface ContentPolicies {
  hasRefundPolicy: boolean;
  refundPolicyUrl: string | null;
  hasPrivacyPolicy: boolean;
  privacyPolicyUrl: string | null;
  hasTermsOfService: boolean;
  termsOfServiceUrl: string | null;
  hasShippingPolicy: boolean;
  shippingPolicyUrl: string | null;
  hasAboutPage: boolean;
  aboutPageUrl: string | null;
}

export interface ContentContact {
  emails: string[];
  phones: string[];
  hasPhysicalAddress: boolean;
  addressHints: string[];
  contactPageUrl: string | null;
}

export interface ShoppingIndicators {
  hasCartOrCheckout: boolean;
  hasProductCatalog: boolean;
  detectedPaymentMethods: string[];
  suspiciousPaymentRequests: string[];
  excessiveDiscountClaims: string[];
  urgencyTactics: string[];
  socialLinks: string[];
}

export interface ContentDetails {
  accessible: boolean;
  statusCode: number | null;
  statusText: string | null;
  title: string | null;
  metaDescription: string | null;
  policies: ContentPolicies;
  contact: ContentContact;
  shopping: ShoppingIndicators;
  htmlSizeBytes: number;
  fetchError: string | null;
}

export interface ReputationDetails {
  googleSafeBrowsing: {
    available: boolean;
    flagged: boolean;
    threatTypes?: string[];
    summary: string;
  };
  virusTotal: {
    available: boolean;
    flagged: boolean;
    maliciousVotes?: number;
    suspiciousVotes?: number;
    harmlessVotes?: number;
    totalVotes?: number;
    summary: string;
  };
}

export interface AnalysisResult {
  id: string;
  timestamp: string;
  originalUrl: string;
  normalizedUrl: string;
  finalUrl: string;
  riskLevel: RiskLevel;
  confidence: ConfidenceLevel;
  confidenceReason: string;
  summary: string;
  recommendations: string[];
  signals: AnalysisSignal[];
  domain: DomainDetails;
  connection: ConnectionDetails;
  content: ContentDetails;
  reputation: ReputationDetails;
  internalRiskScore: number;
  timingMs: number;
}

export interface AnalyzeRequest {
  url: string;
}

export interface AnalyzeErrorResponse {
  error: string;
  code: string;
  details?: string;
  recommendation?: string;
}
