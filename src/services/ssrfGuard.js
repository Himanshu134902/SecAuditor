import dns from "node:dns/promises";
import { URL } from "node:url";

// Checks if an IPv4 address falls inside loopback, private, link-local, or broadcast ranges
function isPrivateOrReservedIP(ip) {
  // Loopback (127.0.0.0/8)
  if (ip.startsWith("127.")) return true;

  // Link-local / Cloud Metadata (169.254.0.0/16)
  if (ip.startsWith("169.254.")) return true;

  // RFC 1918 Private Ranges:
  // 10.0.0.0 - 10.255.255.255
  if (ip.startsWith("10.")) return true;

  // 192.168.0.0 - 192.168.255.255
  if (ip.startsWith("192.168.")) return true;

  // 172.16.0.0 - 172.31.255.255
  const match172 = ip.match(/^172\.(\d+)\./);
  if (match172) {
    const secondOctet = parseInt(match172[1], 10);
    if (secondOctet >= 16 && secondOctet <= 31) return true;
  }

  // 0.0.0.0/8 and broadcast
  if (ip.startsWith("0.") || ip === "255.255.255.255") return true;

  return false;
}

export async function validateTargetSecurity(rawUrl) {
  let parsedUrl;
  try {
    parsedUrl = new URL(rawUrl);
  } catch {
    throw new Error("Invalid URL format supplied.");
  }

  // Only allow standard web protocols
  if (!["http:", "https:"].includes(parsedUrl.protocol)) {
    throw new Error(`Unsupported protocol: ${parsedUrl.protocol}. Only HTTP and HTTPS are permitted.`);
  }

  const hostname = parsedUrl.hostname.toLowerCase();

  // Block local domains
  if (hostname === "localhost" || hostname.endsWith(".local") || hostname.endsWith(".internal")) {
    throw new Error("Access to local or internal network targets is prohibited (SSRF Guard).");
  }

  // Resolve hostname to IPv4 to prevent internal subnet scanning
  try {
    const addresses = await dns.resolve4(hostname);
    if (!addresses || addresses.length === 0) {
      throw new Error("Unable to resolve hostname to an active IP address.");
    }

    for (const ip of addresses) {
      if (isPrivateOrReservedIP(ip)) {
        throw new Error(`Target IP (${ip}) is in a reserved or private network range. Scan blocked.`);
      }
    }
  } catch (err) {
    if (err.code === "ENOTFOUND") {
      throw new Error(`Domain "${hostname}" does not exist or cannot be resolved.`);
    }
    throw err;
  }

  return parsedUrl.toString();
}