export const SECURITY_RULES = [
  {
    id: "csp",
    header: "content-security-policy",
    name: "Content-Security-Policy (CSP)",
    category: "INJECTION",
    severity: "HIGH",
    penalty: 25,
    messageMissing: "Missing Content Security Policy. Leaves site vulnerable to Cross-Site Scripting (XSS) and code injection.",
    messagePresent: "Content Security Policy is enforced.",
    remediation: {
      express: "app.use(helmet.contentSecurityPolicy());",
      nginx: "add_header Content-Security-Policy \"default-src 'self';\" always;"
    },
    evaluate: (val) => Boolean(val && val.trim().length > 0)
  },
  {
    id: "hsts",
    header: "strict-transport-security",
    name: "Strict-Transport-Security (HSTS)",
    category: "ENCRYPTION",
    severity: "HIGH",
    penalty: 20,
    messageMissing: "HSTS not enforced. Connection vulnerable to SSL-stripping and MitM attacks.",
    messagePresent: "HSTS enforced over encrypted channels.",
    remediation: {
      express: "app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));",
      nginx: "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"
    },
    evaluate: (val) => Boolean(val && val.includes("max-age"))
  },
  {
    id: "xfo",
    header: "x-frame-options",
    name: "X-Frame-Options",
    category: "CLICKJACKING",
    severity: "MEDIUM",
    penalty: 15,
    messageMissing: "Missing X-Frame-Options. Site can be embedded inside iframes for clickjacking attacks.",
    messagePresent: "Framing protections active.",
    remediation: {
      express: "app.use(helmet.frameguard({ action: 'sameorigin' }));",
      nginx: "add_header X-Frame-Options \"SAMEORIGIN\" always;"
    },
    evaluate: (val) => Boolean(val && ["DENY", "SAMEORIGIN"].includes(val.toUpperCase()))
  },
  {
    id: "xcto",
    header: "x-content-type-options",
    name: "X-Content-Type-Options",
    category: "MIME",
    severity: "LOW",
    penalty: 10,
    messageMissing: "Missing X-Content-Type-Options. Browsers may sniff responses away from declared content-type.",
    messagePresent: "MIME-type sniffing disabled.",
    remediation: {
      express: "app.use(helmet.noSniff());",
      nginx: "add_header X-Content-Type-Options \"nosniff\" always;"
    },
    evaluate: (val) => Boolean(val && val.toLowerCase().includes("nosniff"))
  },
  {
    id: "referrer_policy",
    header: "referrer-policy",
    name: "Referrer-Policy",
    category: "PRIVACY",
    severity: "MEDIUM",
    penalty: 10,
    messageMissing: "Missing Referrer-Policy. Outbound links may leak internal URL paths and sensitive query parameters.",
    messagePresent: "Referrer path leakage guarded.",
    remediation: {
      express: "app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));",
      nginx: "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;"
    },
    evaluate: (val) => Boolean(val && ["strict-origin-when-cross-origin", "no-referrer", "same-origin"].includes(val.toLowerCase().trim()))
  },
  {
    id: "permissions_policy",
    header: "permissions-policy",
    name: "Permissions-Policy",
    category: "BROWSER_API",
    severity: "LOW",
    penalty: 10,
    messageMissing: "Permissions-Policy not declared. Restricts browser capabilities (camera, microphone, geolocation).",
    messagePresent: "Browser hardware API access restricted.",
    remediation: {
      express: "res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');",
      nginx: "add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;"
    },
    evaluate: (val) => Boolean(val && val.length > 0)
  },
  {
    id: "cookie_security",
    header: "set-cookie",
    name: "Cookie Security (HttpOnly & Secure)",
    category: "AUTHENTICATION",
    severity: "HIGH",
    penalty: 10,
    isCookieRule: true,
    messageMissing: "Session cookies detected without Secure or HttpOnly flags. Vulnerable to theft via client-side scripts.",
    messagePresent: "Cookies properly implement Secure, HttpOnly, or SameSite protections.",
    remediation: {
      express: "res.cookie('token', value, { httpOnly: true, secure: true, sameSite: 'lax' });",
      nginx: "proxy_cookie_path / \"/; Secure; HttpOnly; SameSite=Lax\";"
    }
  },
  {
    id: "info_leak",
    header: "server",
    secondaryHeader: "x-powered-by",
    name: "Technology Version Disclosure",
    category: "DISCLOSURE",
    severity: "LOW",
    penalty: 5,
    messageMissing: "Server technologies are obscured.",
    messagePresent: "Web server software version is exposed to visitors.",
    remediation: {
      express: "app.disable('x-powered-by');",
      nginx: "server_tokens off;"
    },
    evaluateInverse: true 
  }
];