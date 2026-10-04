import axios from "axios";
import { SECURITY_RULES } from "./rules.js";
import { validateTargetSecurity } from "./ssrfGuard.js";

function calculateGrade(score) {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 50) return "D";
  return "F";
}

export function normalizeUrl(inputUrl) {
  let url = inputUrl.trim();
  if (!/^https?:\/\//i.test(url)) {
    url = `https://${url}`;
  }
  return url;
}

export async function runSecurityAudit(targetUrl) {
  const normalized = normalizeUrl(targetUrl);
  await validateTargetSecurity(normalized);

  const response = await axios.get(normalized, {
    timeout: 7000,
    maxRedirects: 4,
    validateStatus: () => true,
    headers: {
      "User-Agent": "SecAuditor-Bot/1.0"
    }
  });

  const rawHeaders = response.headers;
  let score = 100;
  const findings = [];

  for (const rule of SECURITY_RULES) {
    if (rule.evaluateInverse) {
      const serverVal = rawHeaders[rule.header];
      const poweredVal = rawHeaders[rule.secondaryHeader];
      const hasLeak = Boolean(serverVal || poweredVal);

      if (hasLeak) {
        score -= rule.penalty;
        findings.push({
          ruleId: rule.id,
          name: rule.name,
          status: "WARN",
          category: rule.category,
          severity: rule.severity,
          message: rule.messagePresent,
          currentValue: serverVal ? `Server: ${serverVal}` : `X-Powered-By: ${poweredVal}`,
          remediation: rule.remediation
        });
      } else {
        findings.push({
          ruleId: rule.id,
          name: rule.name,
          status: "PASS",
          category: rule.category,
          severity: rule.severity,
          message: rule.messageMissing,
          currentValue: null,
          remediation: null
        });
      }
      continue;
    }

    if (rule.isCookieRule) {
      const cookies = rawHeaders["set-cookie"];
      if (!cookies || cookies.length === 0) {
        findings.push({
          ruleId: rule.id,
          name: rule.name,
          status: "PASS",
          category: rule.category,
          severity: rule.severity,
          message: "No cookies set by endpoint.",
          currentValue: null,
          remediation: null
        });
      } else {
        const rawCookieString = Array.isArray(cookies) ? cookies.join("; ") : cookies;
        const lower = rawCookieString.toLowerCase();
        const isSecure = lower.includes("secure");
        const isHttpOnly = lower.includes("httponly");

        if (isSecure && isHttpOnly) {
          findings.push({
            ruleId: rule.id,
            name: rule.name,
            status: "PASS",
            category: rule.category,
            severity: rule.severity,
            message: rule.messagePresent,
            currentValue: "Secure; HttpOnly",
            remediation: null
          });
        } else {
          score -= rule.penalty;
          findings.push({
            ruleId: rule.id,
            name: rule.name,
            status: "FAIL",
            category: rule.category,
            severity: rule.severity,
            message: rule.messageMissing,
            currentValue: rawCookieString.substring(0, 60) + "...",
            remediation: rule.remediation
          });
        }
      }
      continue;
    }

    const val = rawHeaders[rule.header];
    const passed = rule.evaluate(val);

    if (passed) {
      findings.push({
        ruleId: rule.id,
        name: rule.name,
        status: "PASS",
        category: rule.category,
        severity: rule.severity,
        message: rule.messagePresent,
        currentValue: val,
        remediation: null
      });
    } else {
      score -= rule.penalty;
      findings.push({
        ruleId: rule.id,
        name: rule.name,
        status: "FAIL",
        category: rule.category,
        severity: rule.severity,
        message: rule.messageMissing,
        currentValue: val || null,
        remediation: rule.remediation
      });
    }
  }

  score = Math.max(0, score);

  return {
    testedUrl: normalized,
    statusCode: response.status,
    score,
    grade: calculateGrade(score),
    scannedAt: new Date().toISOString(),
    findings
  };
}