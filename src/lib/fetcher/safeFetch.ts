import { validateUrlForSsrf } from '../security/ssrf';
import { parse as parseTld } from 'tldts';
import { RedirectHop } from '../../types/analyzer';

export interface SafeFetchResult {
  accessible: boolean;
  statusCode: number | null;
  statusText: string | null;
  finalUrl: string;
  finalDomain: string;
  redirects: RedirectHop[];
  redirectCount: number;
  domainChangedOnRedirect: boolean;
  html: string | null;
  headers: Record<string, string>;
  htmlSizeBytes: number;
  fetchError: string | null;
}

const DEFAULT_TIMEOUT_MS = 7000;
const MAX_REDIRECTS = 5;
const MAX_BODY_BYTES = 1024 * 1024 * 2; // 2 MB limit
const USER_AGENT = 'ShopShield-ScamDetector/1.0 (+https://github.com/mayanksupadhye-source/shopshield)';

export async function safeFetchWebsite(
  initialUrl: string,
  timeoutMs: number = DEFAULT_TIMEOUT_MS
): Promise<SafeFetchResult> {
  let currentUrl = initialUrl;
  const initialDomain = parseTld(new URL(initialUrl).hostname).domain || new URL(initialUrl).hostname;
  const redirects: RedirectHop[] = [];
  const visited = new Set<string>();

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    visited.add(currentUrl);

    // 1. SSRF check before every request
    const ssrfCheck = await validateUrlForSsrf(currentUrl);
    if (!ssrfCheck.safe) {
      return {
        accessible: false,
        statusCode: null,
        statusText: null,
        finalUrl: currentUrl,
        finalDomain: parseTld(new URL(currentUrl).hostname).domain || new URL(currentUrl).hostname,
        redirects,
        redirectCount: redirects.length,
        domainChangedOnRedirect: false,
        html: null,
        headers: {},
        htmlSizeBytes: 0,
        fetchError: `Security restriction: ${ssrfCheck.reason || 'Target address is restricted'}`
      };
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      // Manual redirect handling for security and inspection
      const response = await fetch(currentUrl, {
        method: 'GET',
        headers: {
          'User-Agent': USER_AGENT,
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.9',
          'Cache-Control': 'no-cache'
        },
        redirect: 'manual',
        signal: controller.signal
      });

      clearTimeout(timer);

      // Check for redirect status codes (301, 302, 303, 307, 308)
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.get('location');
        if (!location) {
          // Redirect without location header
          break;
        }

        const nextUrl = new URL(location, currentUrl).href;
        const currentDomain = parseTld(new URL(currentUrl).hostname).domain || new URL(currentUrl).hostname;

        redirects.push({
          url: currentUrl,
          status: response.status,
          domain: currentDomain
        });

        if (visited.has(nextUrl)) {
          return {
            accessible: false,
            statusCode: response.status,
            statusText: 'Redirect Loop Detected',
            finalUrl: nextUrl,
            finalDomain: parseTld(new URL(nextUrl).hostname).domain || new URL(nextUrl).hostname,
            redirects,
            redirectCount: redirects.length,
            domainChangedOnRedirect: false,
            html: null,
            headers: {},
            htmlSizeBytes: 0,
            fetchError: 'Redirect loop detected when inspecting website.'
          };
        }

        currentUrl = nextUrl;
        continue;
      }

      // We reached the final destination response
      const headerObj: Record<string, string> = {};
      response.headers.forEach((val, key) => {
        headerObj[key.toLowerCase()] = val;
      });

      const contentType = response.headers.get('content-type') || '';
      const contentLengthHeader = response.headers.get('content-length');

      if (contentLengthHeader && Number.parseInt(contentLengthHeader, 10) > MAX_BODY_BYTES) {
        return {
          accessible: true,
          statusCode: response.status,
          statusText: response.statusText,
          finalUrl: currentUrl,
          finalDomain: parseTld(new URL(currentUrl).hostname).domain || new URL(currentUrl).hostname,
          redirects,
          redirectCount: redirects.length,
          domainChangedOnRedirect: false,
          html: null,
          headers: headerObj,
          htmlSizeBytes: Number.parseInt(contentLengthHeader, 10),
          fetchError: `Response exceeded maximum size limit (${MAX_BODY_BYTES / (1024 * 1024)}MB).`
        };
      }

      // Read response body safely with stream chunk limit
      const reader = response.body?.getReader();
      let html = '';
      let bytesRead = 0;

      if (reader) {
        const decoder = new TextDecoder('utf-8', { fatal: false });
        while (bytesRead < MAX_BODY_BYTES) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value) {
            bytesRead += value.byteLength;
            html += decoder.decode(value, { stream: true });
          }
        }
        html += decoder.decode(); // flush
      } else {
        html = await response.text();
        bytesRead = Buffer.byteLength(html, 'utf-8');
      }

      const finalDomain = parseTld(new URL(currentUrl).hostname).domain || new URL(currentUrl).hostname;
      const domainChangedOnRedirect = redirects.length > 0 && finalDomain.toLowerCase() !== initialDomain.toLowerCase();

      return {
        accessible: response.status < 500, // 2xx, 3xx, 4xx are accessible (even 403/404 are reachable)
        statusCode: response.status,
        statusText: response.statusText,
        finalUrl: currentUrl,
        finalDomain,
        redirects,
        redirectCount: redirects.length,
        domainChangedOnRedirect,
        html,
        headers: headerObj,
        htmlSizeBytes: bytesRead,
        fetchError: null
      };
    } catch (err: unknown) {
      clearTimeout(timer);
      const error = err as Error;
      const isTimeout = error.name === 'AbortError' || error.message?.includes('aborted');

      const finalDomain = parseTld(new URL(currentUrl).hostname).domain || new URL(currentUrl).hostname;
      const domainChangedOnRedirect = redirects.length > 0 && finalDomain.toLowerCase() !== initialDomain.toLowerCase();

      return {
        accessible: false,
        statusCode: null,
        statusText: null,
        finalUrl: currentUrl,
        finalDomain,
        redirects,
        redirectCount: redirects.length,
        domainChangedOnRedirect,
        html: null,
        headers: {},
        htmlSizeBytes: 0,
        fetchError: isTimeout
          ? `Connection timed out after ${timeoutMs / 1000} seconds.`
          : `Failed to connect: ${error.message || 'Network error'}`
      };
    }
  }

  // Exceeded max redirects
  const finalDomain = parseTld(new URL(currentUrl).hostname).domain || new URL(currentUrl).hostname;
  return {
    accessible: false,
    statusCode: null,
    statusText: 'Too Many Redirects',
    finalUrl: currentUrl,
    finalDomain,
    redirects,
    redirectCount: redirects.length,
    domainChangedOnRedirect: false,
    html: null,
    headers: {},
    htmlSizeBytes: 0,
    fetchError: `Exceeded maximum redirect limit of ${MAX_REDIRECTS}.`
  };
}
