export interface Env {
  DISCORD_WEBHOOK_URL: string;
  API_SECRET_TOKEN: string;
  BANNED_HWIDS: KVNamespace;
}

const ROUTE_TELEMETRY = "/v2/sys/telemetry/sync/logs";
const ROUTE_AUTH_CHECK = "/v2/sys/telemetry/auth/check";

const XOR_REASON_KEY = 0x5a;

const APACHE_SERVER_HEADER = "Apache/2.4.57 (Ubuntu)";

const HTML_404 = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>404 Not Found</title>
</head>
<body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>${APACHE_SERVER_HEADER} Server at ${"telemetry.example.workers.dev"} Port 443</address>
</body>
</html>`;

const HTML_403 = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>403 Forbidden</title>
</head>
<body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>${APACHE_SERVER_HEADER} Server at ${"telemetry.example.workers.dev"} Port 443</address>
</body>
</html>`;

const HTML_405 = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>405 Method Not Allowed</title>
</head>
<body>
<h1>Method Not Allowed</h1>
<p>The method is not allowed for the requested URL.</p>
<hr>
<address>${APACHE_SERVER_HEADER} Server at ${"telemetry.example.workers.dev"} Port 443</address>
</body>
</html>`;

function htmlResponse(body: string, status: number): Response {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Server": APACHE_SERVER_HEADER,
      "X-Powered-By": "PHP/8.1.2-1ubuntu2.14",
      "Cache-Control": "no-store",
    },
  });
}

function jsonResponse(data: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "Server": APACHE_SERVER_HEADER,
    },
  });
}

function validateRequest(request: Request, env: Env): Response | null {
  if (request.method !== "POST") {
    return htmlResponse(HTML_404, 404);
  }

  const token = request.headers.get("X-Windows-Internal-Token");
  if (!token || token !== env.API_SECRET_TOKEN) {
    return htmlResponse(HTML_403, 403);
  }

  const ct = request.headers.get("Content-Type") ?? "";
  if (!ct.includes("application/json")) {
    return htmlResponse(HTML_403, 403);
  }

  return null;
}

function decodeReason(hexEncoded: string): string {
  let result = "";
  for (let i = 0; i < hexEncoded.length; i += 2) {
    const byte = parseInt(hexEncoded.slice(i, i + 2), 16);
    if (!isNaN(byte)) {
      result += String.fromCharCode(byte ^ XOR_REASON_KEY);
    }
  }
  return result;
}

function describeViolation(reason: string): string {
  if (reason.startsWith("HACKING_TOOL_DETECTED")) {
    const details = reason.slice("HACKING_TOOL_DETECTED".length).trim();
    return `Hacking tool process or window active ${details}`;
  }

  const map: Record<string, string> = {
    PEB_DEBUGGER_DETECTED: "Debugger detected via PEB `BeingDebugged` / `NtGlobalFlag`",
    HARDWARE_BREAKPOINT_DETECTED: "Hardware breakpoint armed in CPU debug registers (DR0–DR3)",
    TIMING_ANOMALY_DETECTED: "Watchdog thread suspended — possible single-step or VM pause",
    CODE_SECTION_PATCH_DETECTED: "`.text` section SHA-256 mismatch — binary was patched in memory",
    LICENSE_INVALID: "License validation failed",
    MANUAL_VIOLATION_REPORT: "Manually triggered violation report",
  };
  return map[reason] ?? `Unknown violation: \`${reason}\``;
}

// notify discord
async function handleTelemetry(request: Request, env: Env): Promise<Response> {
  let payload: {
    hwid?: string;
    pc?: string;
    reason?: string;
    ts?: string;
  };

  try {
    payload = await request.json() as typeof payload;
  } catch {
    return htmlResponse(HTML_404, 404);
  }

  const hwid = (payload.hwid ?? "UNKNOWN_HWID").slice(0, 128);
  const pc = (payload.pc ?? "UNKNOWN_PC").slice(0, 64);
  const rawReason = (payload.reason ?? "").slice(0, 256);
  const ts = (payload.ts ?? new Date().toISOString()).slice(0, 32);

  const decodedReason = decodeReason(rawReason);
  const friendlyReason = describeViolation(decodedReason);

  const reportedAt = new Date().toISOString();

  const discordPayload = {
    username: "Security",
    avatar_url: "https://i.pinimg.com/736x/7b/c1/bd/7bc1bdf90bf9b5051d9a4c9edacd114c.jpg",
    embeds: [
      {
        title: "DETECT",
        description: `detect crack, x64dbg, ida pro, ohter...**`,
        color: 0xff0000,
        thumbnail: {
          url: "https://i.imgur.com/wSTFkRM.png",
        },
        fields: [
          {
            name: "Hardware ID (HWID)",
            value: `\`\`\`${hwid}\`\`\``,
            inline: false,
          },
          {
            name: "Computer Name",
            value: `\`${pc}\``,
            inline: true,
          },
          {
            name: "Client Timestamp",
            value: `\`${ts}\``,
            inline: true,
          },
          {
            name: "Violation Code",
            value: `\`${decodedReason}\``,
            inline: false,
          },
          {
            name: "case",
            value: friendlyReason,
            inline: false,
          },
        ],
        footer: {
          text: `Report received at ${reportedAt}`,
        },
        timestamp: reportedAt,
      },
    ],
  };

  const discordFetch = fetch(env.DISCORD_WEBHOOK_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(discordPayload),
  });

  const banRecord = JSON.stringify({
    hwid,
    pc,
    reason: decodedReason,
    clientTs: ts,
    bannedAt: reportedAt,
  });

  const kvPut = env.BANNED_HWIDS.put(hwid, banRecord);
  await Promise.all([discordFetch, kvPut]);

  return jsonResponse({ status: "ok" }, 200);
}

//  HWID  license service
async function handleAuthCheck(request: Request, env: Env): Promise<Response> {
  let payload: { hwid?: string };

  try {
    payload = await request.json() as { hwid?: string };
  } catch {
    return jsonResponse({ status: "error", message: "invalid_json" }, 400);
  }

  const hwid = (payload.hwid ?? "").trim().slice(0, 128);
  if (!hwid) {
    return jsonResponse({ status: "error", message: "missing_hwid" }, 400);
  }

  const banRecord = await env.BANNED_HWIDS.get(hwid, { type: "text" });

  if (banRecord !== null) {
    let banData: Record<string, unknown> = {};
    try {
      banData = JSON.parse(banRecord) as Record<string, unknown>;
    } catch {
      banData = { raw: banRecord };
    }

    return jsonResponse({
      status: "banned",
      bannedAt: banData.bannedAt ?? "unknown",
      reason: banData.reason ?? "unknown",
    }, 200);
  }

  return jsonResponse({ status: "ok" }, 200);
}

export default {
  async fetch(
    request: Request,
    env: Env,
    _ctx: ExecutionContext
  ): Promise<Response> {

    const url = new URL(request.url);
    const path = url.pathname;

    if (path === ROUTE_TELEMETRY) {
      const authError = validateRequest(request, env);
      if (authError) return authError;
      return handleTelemetry(request, env);
    }

    if (path === ROUTE_AUTH_CHECK) {
      const authError = validateRequest(request, env);
      if (authError) return authError;
      return handleAuthCheck(request, env);
    }

    return htmlResponse(HTML_404, 404);
  },
};
