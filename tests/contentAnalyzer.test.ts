import { describe, it, expect } from 'vitest';
import { analyzeHtmlContent } from '../src/lib/services/contentAnalyzer';

describe('Website Content & Shopping Analyzer', () => {
  it('handles empty or inaccessible response cleanly', () => {
    const res = analyzeHtmlContent(null, 'https://example.com', null, 'Connection failed');
    expect(res.accessible).toBe(false);
    expect(res.policies.hasRefundPolicy).toBe(false);
    expect(res.contact.emails).toEqual([]);
    expect(res.shopping.hasCartOrCheckout).toBe(false);
  });

  it('detects policies and contact details on legitimate stores', () => {
    const mockHtml = `
      <!DOCTYPE html>
      <html>
        <head>
          <title>Apex Sports Official Gear</title>
          <meta name="description" content="Official athletic apparel and footwear.">
        </head>
        <body>
          <header>
            <nav>
              <a href="/products">Shop Catalog</a>
              <a href="/cart">Cart (0)</a>
            </nav>
          </header>
          <main>
            <h1>Running Shoes - $129.99</h1>
            <p>High performance footwear for distance runners.</p>
            <button class="add-to-cart">Add to Cart</button>
          </main>
          <footer>
            <div>
              <a href="/legal/refund-policy">Returns & Refund Policy</a>
              <a href="/legal/privacy">Privacy Policy</a>
              <a href="/legal/terms">Terms of Service</a>
              <a href="/shipping-delivery">Shipping Policy</a>
              <a href="/about-us">About Our Company</a>
            </div>
            <div>
              <p>Contact us: <a href="mailto:support@apexsports.com">support@apexsports.com</a></p>
              <p>Call us: <a href="tel:+18005550199">+1 (800) 555-0199</a></p>
              <address>123 Commerce Boulevard, Suite 400, Chicago, IL 60601</address>
            </div>
            <div>
              <p>We accept Visa, Mastercard, American Express, and PayPal.</p>
            </div>
          </footer>
        </body>
      </html>
    `;

    const res = analyzeHtmlContent(mockHtml, 'https://apexsports.com', 200, null);

    expect(res.accessible).toBe(true);
    expect(res.title).toBe('Apex Sports Official Gear');
    expect(res.policies.hasRefundPolicy).toBe(true);
    expect(res.policies.hasPrivacyPolicy).toBe(true);
    expect(res.policies.hasTermsOfService).toBe(true);
    expect(res.policies.hasShippingPolicy).toBe(true);
    expect(res.policies.hasAboutPage).toBe(true);

    expect(res.contact.emails).toContain('support@apexsports.com');
    expect(res.contact.phones.length).toBeGreaterThan(0);
    expect(res.contact.hasPhysicalAddress).toBe(true);

    expect(res.shopping.hasCartOrCheckout).toBe(true);
    expect(res.shopping.hasProductCatalog).toBe(true);
    expect(res.shopping.detectedPaymentMethods).toContain('Visa');
    expect(res.shopping.detectedPaymentMethods).toContain('PayPal');
    expect(res.shopping.suspiciousPaymentRequests).toEqual([]);
    expect(res.shopping.excessiveDiscountClaims).toEqual([]);
  });

  it('detects scam patterns: wire transfer only, 95% off, and pressure urgency', () => {
    const mockScamHtml = `
      <!DOCTYPE html>
      <html>
        <head><title>SUPER CLEARANCE OUTLET</title></head>
        <body>
          <h1>FACTORY BLOWOUT SALE 95% OFF!</h1>
          <p>Entire store 90% off today only! Hurry, limited time offer!</p>
          <div class="countdown-timer">Only 1 left in stock - cart expires in 04:59</div>

          <div class="payment-notice">
            <p>IMPORTANT: Due to high volume, direct wire transfer only is accepted.</p>
            <p>You can also pay with gift card (Amazon gift card code or Steam card).</p>
          </div>
          <footer>
            <p>© 2026 Bargain Outlet. All rights reserved.</p>
          </footer>
        </body>
      </html>
    `;

    const res = analyzeHtmlContent(mockScamHtml, 'https://scam-store-deals.xyz', 200, null);

    expect(res.accessible).toBe(true);
    expect(res.policies.hasRefundPolicy).toBe(false);
    expect(res.policies.hasPrivacyPolicy).toBe(false);
    expect(res.policies.hasTermsOfService).toBe(false);
    expect(res.contact.emails).toEqual([]);
    expect(res.contact.hasPhysicalAddress).toBe(false);

    expect(res.shopping.suspiciousPaymentRequests.length).toBeGreaterThan(0);
    expect(res.shopping.suspiciousPaymentRequests.some(p => p.includes('Wire Transfer'))).toBe(true);
    expect(res.shopping.suspiciousPaymentRequests.some(p => p.includes('Gift Card'))).toBe(true);

    expect(res.shopping.excessiveDiscountClaims.length).toBeGreaterThan(0);
    expect(res.shopping.urgencyTactics.length).toBeGreaterThan(0);
  });
});
