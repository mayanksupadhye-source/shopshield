import { ReputationDetails } from '../../types/analyzer';

export async function checkReputationApis(targetUrl: string): Promise<ReputationDetails> {
  const result: ReputationDetails = {
    googleSafeBrowsing: {
      available: false,
      flagged: false,
      summary: 'Not configured (GOOGLE_SAFE_BROWSING_API_KEY is not set).'
    },
    virusTotal: {
      available: false,
      flagged: false,
      summary: 'Not configured (VIRUSTOTAL_API_KEY is not set).'
    }
  };

  const safeBrowsingKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY?.trim();
  const virusTotalKey = process.env.VIRUSTOTAL_API_KEY?.trim();

  // 1. Google Safe Browsing Lookup v4
  if (safeBrowsingKey) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 4000);

      const response = await fetch(
        `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(safeBrowsingKey)}`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            client: {
              clientId: 'shopshield-detector',
              clientVersion: '1.0.0'
            },
            threatInfo: {
              threatTypes: [
                'MALWARE',
                'SOCIAL_ENGINEERING',
                'UNWANTED_SOFTWARE',
                'POTENTIALLY_HARMFUL_APPLICATION'
              ],
              platformTypes: ['ANY_PLATFORM'],
              threatEntryTypes: ['URL'],
              threatEntries: [{ url: targetUrl }]
            }
          }),
          signal: controller.signal
        }
      );

      clearTimeout(timer);

      if (response.ok) {
        const data = await response.json() as { matches?: Array<{ threatType: string }> };
        if (Array.isArray(data.matches) && data.matches.length > 0) {
          const threats = Array.from(new Set(data.matches.map(m => m.threatType)));
          result.googleSafeBrowsing = {
            available: true,
            flagged: true,
            threatTypes: threats,
            summary: `Flagged as malicious by Google Safe Browsing (${threats.join(', ')}).`
          };
        } else {
          result.googleSafeBrowsing = {
            available: true,
            flagged: false,
            summary: 'Clean: No threats listed in Google Safe Browsing database.'
          };
        }
      } else {
        result.googleSafeBrowsing = {
          available: false,
          flagged: false,
          summary: `Safe Browsing query failed (HTTP ${response.status}).`
        };
      }
    } catch (err: unknown) {
      const error = err as Error;
      result.googleSafeBrowsing = {
        available: false,
        flagged: false,
        summary: `Safe Browsing unavailable: ${error.message}`
      };
    }
  }

  // 2. VirusTotal API v3
  if (virusTotalKey) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 4000);

      // VirusTotal URL ID is base64url encoded without padding '='
      const urlId = Buffer.from(targetUrl)
        .toString('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');

      const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
        method: 'GET',
        headers: {
          'x-apikey': virusTotalKey,
          'Accept': 'application/json'
        },
        signal: controller.signal
      });

      clearTimeout(timer);

      if (response.ok) {
        const data = await response.json() as {
          data?: {
            attributes?: {
              last_analysis_stats?: {
                malicious?: number;
                suspicious?: number;
                harmless?: number;
                undetected?: number;
              };
            };
          };
        };

        const stats = data.data?.attributes?.last_analysis_stats;
        if (stats) {
          const malicious = stats.malicious || 0;
          const suspicious = stats.suspicious || 0;
          const harmless = stats.harmless || 0;
          const undetected = stats.undetected || 0;
          const total = malicious + suspicious + harmless + undetected;
          const isFlagged = malicious >= 1 || suspicious >= 2;

          result.virusTotal = {
            available: true,
            flagged: isFlagged,
            maliciousVotes: malicious,
            suspiciousVotes: suspicious,
            harmlessVotes: harmless,
            totalVotes: total,
            summary: isFlagged
              ? `Flagged by ${malicious} security vendor${malicious === 1 ? '' : 's'} on VirusTotal.`
              : `Checked against ${total} vendors on VirusTotal (${harmless} harmless, 0 malicious).`
          };
        }
      } else if (response.status === 404) {
        result.virusTotal = {
          available: true,
          flagged: false,
          summary: 'URL has not yet been scanned or cataloged on VirusTotal.'
        };
      } else {
        result.virusTotal = {
          available: false,
          flagged: false,
          summary: `VirusTotal query returned HTTP ${response.status}.`
        };
      }
    } catch (err: unknown) {
      const error = err as Error;
      result.virusTotal = {
        available: false,
        flagged: false,
        summary: `VirusTotal lookup unavailable: ${error.message}`
      };
    }
  }

  return result;
}
