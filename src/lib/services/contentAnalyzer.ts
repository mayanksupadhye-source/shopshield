import * as cheerio from 'cheerio';
import {
  ContentDetails,
  ContentPolicies,
  ContentContact,
  ShoppingIndicators
} from '../../types/analyzer';

const KNOWN_PAYMENT_PROVIDERS = [
  { name: 'PayPal', pattern: /\bpaypal\b/i },
  { name: 'Stripe', pattern: /\bstripe\b/i },
  { name: 'Visa', pattern: /\bvisa\b/i },
  { name: 'Mastercard', pattern: /\bmastercard\b/i },
  { name: 'American Express', pattern: /\b(american express|amex)\b/i },
  { name: 'Apple Pay', pattern: /\bapple\s*pay\b/i },
  { name: 'Google Pay', pattern: /\bgoogle\s*pay\b/i },
  { name: 'Shopify Payments', pattern: /\bshopify\s*(pay|payments)?\b/i },
  { name: 'Klarna', pattern: /\bklarna\b/i },
  { name: 'Afterpay', pattern: /\bafterpay\b/i },
  { name: 'Square', pattern: /\bsquare\s*(pay)?\b/i }
];

const SUSPICIOUS_PAYMENT_PATTERNS = [
  { name: 'Direct Wire Transfer / Bank Transfer Only', pattern: /\b(wire transfer only|direct bank transfer only|direct wire required)\b/i },
  { name: 'Western Union / MoneyGram Only', pattern: /\b(western union|moneygram)\b/i },
  { name: 'Cryptocurrency-Only Payment', pattern: /\b(bitcoin only|crypto only|pay with btc only|usdt only|send to wallet address)\b/i },
  { name: 'Gift Card Payment Request', pattern: /\b(pay with gift card|amazon gift card code|steam card code|apple gift card)\b/i },
  { name: 'Zelle / Cash App / Friends & Family Only', pattern: /\b(zelle only|cashapp only|cash app only|friends and family only)\b/i }
];

const UNREALISTIC_DISCOUNT_PATTERNS = [
  /\b(8[5-9]|9[0-9])%\s*off\b/i,
  /\bentire\s+store\s+(8[0-9]|9[0-9])%\s*off\b/i,
  /\b(warehouse|factory|clearance)\s+liquidation\s+(8[0-9]|9[0-9])%\b/i,
  /\beverything\s+\$\d{1,2}\s+today\s+only\b/i,
  /\b(blowout|super)\s+sale\s+9[0-9]%\s*off\b/i
];

const URGENCY_PATTERNS = [
  /\bonly\s+[1-3]\s+left\s+in\s+stock\b/i,
  /\border\s+within\s+\d{1,2}\s*:\s*\d{2}\b/i,
  /\bcart\s+expires\s+in\b/i,
  /\bhurry[,\s]+limited\s+time\s+offer\b/i,
  /\bclaim\s+before\s+timer\s+ends\b/i,
  /\b\d+\s+people\s+viewing\s+this\s+right\s+now\b/i
];

const SOCIAL_DOMAINS = [
  'facebook.com',
  'instagram.com',
  'twitter.com',
  'x.com',
  'pinterest.com',
  'tiktok.com',
  'youtube.com',
  'linkedin.com'
];

export function analyzeHtmlContent(
  html: string | null,
  baseUrl: string,
  statusCode: number | null,
  fetchError: string | null
): ContentDetails {
  if (!html || html.trim().length === 0) {
    return {
      accessible: false,
      statusCode,
      statusText: statusCode ? `HTTP ${statusCode}` : null,
      title: null,
      metaDescription: null,
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
        hasCartOrCheckout: false,
        hasProductCatalog: false,
        detectedPaymentMethods: [],
        suspiciousPaymentRequests: [],
        excessiveDiscountClaims: [],
        urgencyTactics: [],
        socialLinks: []
      },
      htmlSizeBytes: 0,
      fetchError
    };
  }

  const $ = cheerio.load(html);
  const bodyText = $('body').text().replace(/\s+/g, ' ');
  const pageTitle = $('title').first().text().trim() || null;
  const metaDesc = $('meta[name="description"], meta[property="og:description"]').first().attr('content')?.trim() || null;

  // 1. Policies & Legal pages
  const policies: ContentPolicies = {
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
  };

  $('a').each((_, el) => {
    const href = $(el).attr('href')?.trim() || '';
    const text = $(el).text().toLowerCase().trim();
    const linkStr = `${href} ${text}`.toLowerCase();

    const resolveUrl = (path: string) => {
      try {
        return new URL(path, baseUrl).href;
      } catch {
        return path;
      }
    };

    if (!policies.hasRefundPolicy && (linkStr.includes('refund') || linkStr.includes('return-policy') || linkStr.includes('returns') || text.includes('returns & refund'))) {
      policies.hasRefundPolicy = true;
      policies.refundPolicyUrl = resolveUrl(href);
    }

    if (!policies.hasPrivacyPolicy && (linkStr.includes('privacy') || text.includes('privacy policy'))) {
      policies.hasPrivacyPolicy = true;
      policies.privacyPolicyUrl = resolveUrl(href);
    }

    if (!policies.hasTermsOfService && (linkStr.includes('terms') || linkStr.includes('tos') || text.includes('terms of service') || text.includes('terms & conditions'))) {
      policies.hasTermsOfService = true;
      policies.termsOfServiceUrl = resolveUrl(href);
    }

    if (!policies.hasShippingPolicy && (linkStr.includes('shipping') || linkStr.includes('delivery') || text.includes('shipping policy'))) {
      policies.hasShippingPolicy = true;
      policies.shippingPolicyUrl = resolveUrl(href);
    }

    if (!policies.hasAboutPage && (linkStr.includes('about-us') || linkStr.includes('about') || text.includes('about us') || text.includes('our story'))) {
      policies.hasAboutPage = true;
      policies.aboutPageUrl = resolveUrl(href);
    }
  });

  // 2. Contact details
  const emails = new Set<string>();
  const phones = new Set<string>();
  let contactPageUrl: string | null = null;

  // mailto: links
  $('a[href^="mailto:"]').each((_, el) => {
    const raw = $(el).attr('href')?.replace(/^mailto:/i, '').split('?')[0].trim();
    if (raw && raw.includes('@') && !raw.includes('example.com') && !raw.includes('domain.com')) {
      emails.add(raw.toLowerCase());
    }
  });

  // text email regex
  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
  const foundEmails = bodyText.match(emailRegex) || [];
  for (const e of foundEmails) {
    const low = e.toLowerCase();
    if (!low.includes('example.com') && !low.includes('domain.com') && !low.includes('.png') && !low.includes('.jpg') && !low.includes('w3.org')) {
      emails.add(low);
    }
  }

  // tel: links
  $('a[href^="tel:"]').each((_, el) => {
    const raw = $(el).attr('href')?.replace(/^tel:/i, '').trim();
    if (raw && raw.length >= 7) {
      phones.add(raw);
    }
  });

  // Contact page link
  $('a').each((_, el) => {
    const href = $(el).attr('href')?.trim() || '';
    const text = $(el).text().toLowerCase().trim();
    if (!contactPageUrl && (href.includes('contact') || text === 'contact' || text === 'contact us' || text === 'get in touch')) {
      try {
        contactPageUrl = new URL(href, baseUrl).href;
      } catch {
        contactPageUrl = href;
      }
    }
  });

  // Physical address inspection
  let hasPhysicalAddress = false;
  const addressHints: string[] = [];

  // Check Schema.org JSON-LD
  $('script[type="application/ld+json"]').each((_, el) => {
    try {
      const json = JSON.parse($(el).html() || '{}') as Record<string, unknown>;
      const checkAddress = (obj: unknown) => {
        if (!obj || typeof obj !== 'object') return;
        const record = obj as Record<string, unknown>;
        if (record['@type'] === 'PostalAddress' || record.address) {
          hasPhysicalAddress = true;
          addressHints.push('Verified structured PostalAddress metadata');
        }
      };
      checkAddress(json);
      if (Array.isArray(json['@graph'])) {
        json['@graph'].forEach(checkAddress);
      }
    } catch {
      // ignore JSON parse errors in inline scripts
    }
  });

  // Check <address> tag or footer address text
  if (!hasPhysicalAddress) {
    const addressTag = $('address').text().trim();
    if (addressTag.length > 10) {
      hasPhysicalAddress = true;
      addressHints.push(addressTag.slice(0, 100));
    }
  }

  if (!hasPhysicalAddress) {
    const footerText = $('footer, [class*="footer"], [id*="footer"]').text();
    const addressMatch = footerText.match(/\b\d{1,5}\s+[A-Za-z0-9\s,]{4,35}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Suite|Ste|Floor|Fl|Highway|Hwy|Way|Drive|Dr|Lane|Ln)[,\s]+[A-Za-z\s]+[,\s]+[A-Z0-9\s-]{3,10}\b/i);
    if (addressMatch) {
      hasPhysicalAddress = true;
      addressHints.push(addressMatch[0].trim());
    }
  }

  // 3. Shopping signals
  let hasCartOrCheckout = false;
  $('a, button, form').each((_, el) => {
    const href = $(el).attr('href')?.toLowerCase() || '';
    const text = $(el).text().toLowerCase();
    const cls = $(el).attr('class')?.toLowerCase() || '';
    const id = $(el).attr('id')?.toLowerCase() || '';
    const action = $(el).attr('action')?.toLowerCase() || '';

    if (
      href.includes('cart') ||
      href.includes('checkout') ||
      action.includes('checkout') ||
      text.includes('add to cart') ||
      text.includes('buy now') ||
      text.includes('checkout') ||
      cls.includes('add-to-cart') ||
      id.includes('cart')
    ) {
      hasCartOrCheckout = true;
    }
  });

  // Product catalog check: price patterns or product schema
  const priceRegex = /([$€£₹]\s*\d+([.,]\d{2})?|\b\d+([.,]\d{2})?\s*(USD|EUR|GBP|INR)\b)/g;
  const priceMatches = bodyText.match(priceRegex) || [];
  const hasProductCatalog =
    priceMatches.length >= 1 ||
    $('[class*="product"], [id*="product"], [itemtype*="Product"], a[href*="product"], a[href*="shop"]').length > 0;

  // Payment methods
  const detectedPaymentMethods: string[] = [];
  for (const provider of KNOWN_PAYMENT_PROVIDERS) {
    if (provider.pattern.test(bodyText) || provider.pattern.test(html)) {
      detectedPaymentMethods.push(provider.name);
    }
  }

  // Suspicious payment requests
  const suspiciousPaymentRequests: string[] = [];
  for (const susp of SUSPICIOUS_PAYMENT_PATTERNS) {
    if (susp.pattern.test(bodyText)) {
      suspiciousPaymentRequests.push(susp.name);
    }
  }

  // Unrealistic discounts
  const excessiveDiscountClaims: string[] = [];
  for (const pattern of UNREALISTIC_DISCOUNT_PATTERNS) {
    const match = bodyText.match(pattern);
    if (match) {
      excessiveDiscountClaims.push(match[0].trim());
    }
  }

  // Urgency tactics
  const urgencyTactics: string[] = [];
  for (const pattern of URGENCY_PATTERNS) {
    const match = bodyText.match(pattern);
    if (match) {
      urgencyTactics.push(match[0].trim());
    }
  }

  // Check countdown timers in DOM
  if ($('[class*="countdown"], [id*="countdown"], [class*="timer"], [id*="timer"]').length > 0) {
    urgencyTactics.push('Countdown timer element detected');
  }

  // Social links
  const socialLinks: string[] = [];
  $('a[href]').each((_, el) => {
    const href = $(el).attr('href')?.trim() || '';
    for (const domain of SOCIAL_DOMAINS) {
      if (href.includes(domain) && !socialLinks.includes(domain)) {
        socialLinks.push(domain);
      }
    }
  });

  return {
    accessible: true,
    statusCode,
    statusText: statusCode ? `HTTP ${statusCode}` : null,
    title: pageTitle,
    metaDescription: metaDesc,
    policies,
    contact: {
      emails: Array.from(emails).slice(0, 5),
      phones: Array.from(phones).slice(0, 5),
      hasPhysicalAddress,
      addressHints: addressHints.slice(0, 2),
      contactPageUrl
    },
    shopping: {
      hasCartOrCheckout,
      hasProductCatalog,
      detectedPaymentMethods,
      suspiciousPaymentRequests,
      excessiveDiscountClaims: Array.from(new Set(excessiveDiscountClaims)),
      urgencyTactics: Array.from(new Set(urgencyTactics)),
      socialLinks
    },
    htmlSizeBytes: Buffer.byteLength(html, 'utf-8'),
    fetchError
  };
}
