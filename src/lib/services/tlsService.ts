import tls from 'node:tls';
import net from 'node:net';

export interface TlsCheckResult {
  tlsAvailable: boolean;
  tlsValid: boolean | null;
  issuer: string | null;
  subject: string | null;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  hostnameMismatch: boolean;
  authorizationError: string | null;
  sanList: string[];
}

export async function checkTlsCertificate(
  hostname: string,
  port: number = 443,
  timeoutMs: number = 4500
): Promise<TlsCheckResult> {
  // If host is an IP, SNI behaves differently, but we can still inspect
  return new Promise<TlsCheckResult>(resolve => {
    let settled = false;

    const cleanupAndResolve = (res: TlsCheckResult) => {
      if (!settled) {
        settled = true;
        resolve(res);
      }
    };

    const timer = setTimeout(() => {
      try {
        socket.destroy();
      } catch {
        // ignore
      }
      cleanupAndResolve({
        tlsAvailable: false,
        tlsValid: null,
        issuer: null,
        subject: null,
        validFrom: null,
        validTo: null,
        daysRemaining: null,
        hostnameMismatch: false,
        authorizationError: 'TLS handshake connection timed out',
        sanList: []
      });
    }, timeoutMs);

    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: net.isIP(hostname) ? undefined : hostname,
        rejectUnauthorized: false // We inspect the error manually via socket.authorized
      },
      () => {
        clearTimeout(timer);
        try {
          const cert = socket.getPeerCertificate(true);
          const authorized = socket.authorized;
          const authError = socket.authorizationError ? String(socket.authorizationError) : null;

          if (!cert || Object.keys(cert).length === 0) {
            socket.end();
            return cleanupAndResolve({
              tlsAvailable: false,
              tlsValid: null,
              issuer: null,
              subject: null,
              validFrom: null,
              validTo: null,
              daysRemaining: null,
              hostnameMismatch: false,
              authorizationError: 'No peer certificate presented',
              sanList: []
            });
          }

          // Parse SAN list
          const sanString = cert.subjectaltname || '';
          const sanList = sanString
            .split(',')
            .map(s => s.trim().replace(/^DNS:/i, '').toLowerCase())
            .filter(Boolean);

          // Check hostname match against SAN or CN
          const rawCn = cert.subject?.CN;
          const cn = (Array.isArray(rawCn) ? rawCn[0] || '' : rawCn || '').toLowerCase();
          const targetHost = hostname.toLowerCase();

          const matchesHost = (pattern: string, host: string) => {
            if (pattern === host) return true;
            if (pattern.startsWith('*.')) {
              const base = pattern.slice(2);
              const hostParts = host.split('.');
              return hostParts.slice(1).join('.') === base;
            }
            return false;
          };

          const matched = sanList.some(san => matchesHost(san, targetHost)) || matchesHost(cn, targetHost);
          const hostnameMismatch = !matched;

          const validToDate = cert.valid_to ? new Date(cert.valid_to) : null;
          const daysRemaining = validToDate
            ? Math.round((validToDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24))
            : null;

          const rawIssuer = cert.issuer ? cert.issuer.O || cert.issuer.CN : null;
          const issuerStr = Array.isArray(rawIssuer) ? rawIssuer.join(', ') : (rawIssuer || null);

          const rawSubject = cert.subject ? cert.subject.CN || cert.subject.O : null;
          const subjectStr = Array.isArray(rawSubject) ? rawSubject.join(', ') : (rawSubject || null);

          socket.end();
          return cleanupAndResolve({
            tlsAvailable: true,
            tlsValid: authorized && !hostnameMismatch && (daysRemaining !== null ? daysRemaining > 0 : true),
            issuer: issuerStr,
            subject: subjectStr,
            validFrom: cert.valid_from || null,
            validTo: cert.valid_to || null,
            daysRemaining,
            hostnameMismatch,
            authorizationError: authError,
            sanList
          });
        } catch (err: unknown) {
          const error = err as Error;
          socket.destroy();
          return cleanupAndResolve({
            tlsAvailable: false,
            tlsValid: null,
            issuer: null,
            subject: null,
            validFrom: null,
            validTo: null,
            daysRemaining: null,
            hostnameMismatch: false,
            authorizationError: error.message,
            sanList: []
          });
        }
      }
    );

    socket.on('error', err => {
      clearTimeout(timer);
      try {
        socket.destroy();
      } catch {
        // ignore
      }
      cleanupAndResolve({
        tlsAvailable: false,
        tlsValid: null,
        issuer: null,
        subject: null,
        validFrom: null,
        validTo: null,
        daysRemaining: null,
        hostnameMismatch: false,
        authorizationError: err.message,
        sanList: []
      });
    });
  });
}
