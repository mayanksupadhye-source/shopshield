export interface RdapResult {
  status: 'verified' | 'unavailable' | 'error';
  registrationDate: string | null;
  domainAgeDays: number | null;
  registrar: string | null;
  details: string;
}

export async function lookupDomainRdap(
  registrableDomain: string,
  timeoutMs: number = 3800
): Promise<RdapResult> {
  if (!registrableDomain || registrableDomain.includes(':')) {
    return {
      status: 'unavailable',
      registrationDate: null,
      domainAgeDays: null,
      registrar: null,
      details: 'Domain registration info unavailable for this host.'
    };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const rdapUrl = `https://rdap.org/domain/${encodeURIComponent(registrableDomain)}`;
    const response = await fetch(rdapUrl, {
      method: 'GET',
      headers: {
        'Accept': 'application/rdap+json, application/json',
        'User-Agent': 'ShopShield-ScamDetector/1.0 (+https://github.com/mayanksupadhye-source/shopshield)'
      },
      signal: controller.signal
    });

    clearTimeout(timer);

    if (!response.ok) {
      return {
        status: 'unavailable',
        registrationDate: null,
        domainAgeDays: null,
        registrar: null,
        details: `RDAP service returned status ${response.status} (registration data unavailable).`
      };
    }

    const data = await response.json() as {
      events?: Array<{ eventAction?: string; eventDate?: string }>;
      entities?: Array<{
        roles?: string[];
        vcardArray?: unknown[];
        legalName?: string;
        handle?: string;
      }>;
    };

    // Find registration date in events
    let registrationDateStr: string | null = null;
    if (Array.isArray(data.events)) {
      const regEvent = data.events.find(
        e => e.eventAction === 'registration' || e.eventAction === 'created'
      );
      if (regEvent?.eventDate) {
        registrationDateStr = regEvent.eventDate;
      }
    }

    // Find registrar name in entities
    let registrarName: string | null = null;
    if (Array.isArray(data.entities)) {
      const registrarEntity = data.entities.find(e =>
        Array.isArray(e.roles) && e.roles.includes('registrar')
      );
      if (registrarEntity) {
        if (registrarEntity.legalName) {
          registrarName = registrarEntity.legalName;
        } else if (Array.isArray(registrarEntity.vcardArray) && Array.isArray(registrarEntity.vcardArray[1])) {
          // vcardArray format: ["vcard", [["fn", {}, "text", "GoDaddy.com, LLC"], ...]]
          const fnEntry = (registrarEntity.vcardArray[1] as Array<unknown[]>).find(
            item => Array.isArray(item) && item[0] === 'fn'
          );
          if (fnEntry && typeof fnEntry[3] === 'string') {
            registrarName = fnEntry[3];
          }
        }
        if (!registrarName && registrarEntity.handle) {
          registrarName = registrarEntity.handle;
        }
      }
    }

    let domainAgeDays: number | null = null;
    if (registrationDateStr) {
      const regTime = new Date(registrationDateStr).getTime();
      if (!Number.isNaN(regTime)) {
        domainAgeDays = Math.max(0, Math.floor((Date.now() - regTime) / (1000 * 60 * 60 * 24)));
      }
    }

    if (registrationDateStr) {
      return {
        status: 'verified',
        registrationDate: registrationDateStr,
        domainAgeDays,
        registrar: registrarName,
        details: domainAgeDays !== null
          ? `Domain registered ${domainAgeDays} days ago (${new Date(registrationDateStr).toLocaleDateString()}) via ${registrarName || 'verified registrar'}.`
          : `Domain registration date: ${registrationDateStr}.`
      };
    }

    return {
      status: 'unavailable',
      registrationDate: null,
      domainAgeDays: null,
      registrar: registrarName,
      details: 'Domain registration events not specified in RDAP response.'
    };
  } catch (err: unknown) {
    clearTimeout(timer);
    const error = err as Error;
    return {
      status: 'unavailable',
      registrationDate: null,
      domainAgeDays: null,
      registrar: null,
      details: error.name === 'AbortError'
        ? 'RDAP lookup timed out.'
        : 'Domain registration info lookup unavailable.'
    };
  }
}
