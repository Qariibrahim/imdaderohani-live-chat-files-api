const ALLOWED_ORIGINS = new Set([
  "https://qrc.imdaderohani.in",
]);

const FIREBASE_API_KEY = "AIzaSyC6bhgW8pXu_LFlJ9SvTrveXj-nKLsdQws";
const ADMIN_UID = "7ybBWGwZipX3sM9iLrdGIgOo3l92";
const RETENTION_DAYS = 30;
const DAILY_FILE_LIMIT = 20;
const DAILY_BYTE_LIMIT = 100 * 1024 * 1024;

const TYPE_RULES = new Map([
  ["image/jpeg", { category: "image", max: 5 * 1024 * 1024 }],
  ["image/png", { category: "image", max: 5 * 1024 * 1024 }],
  ["image/webp", { category: "image", max: 5 * 1024 * 1024 }],
  ["image/gif", { category: "image", max: 5 * 1024 * 1024 }],
  ["application/pdf", { category: "pdf", max: 10 * 1024 * 1024 }],
  ["audio/mpeg", { category: "audio", max: 15 * 1024 * 1024 }],
  ["audio/mp4", { category: "audio", max: 15 * 1024 * 1024 }],
  ["audio/ogg", { category: "audio", max: 15 * 1024 * 1024 }],
  ["audio/wav", { category: "audio", max: 15 * 1024 * 1024 }],
  ["audio/webm", { category: "audio", max: 15 * 1024 * 1024 }],
  ["video/mp4", { category: "video", max: 25 * 1024 * 1024 }],
  ["video/webm", { category: "video", max: 25 * 1024 * 1024 }],
  ["video/quicktime", { category: "video", max: 25 * 1024 * 1024 }],
]);

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const cors = corsHeaders(origin);

    if (request.method === "OPTIONS") {
      if (!ALLOWED_ORIGINS.has(origin)) {
        return json({ ok: false, error: "ORIGIN_NOT_ALLOWED" }, 403, cors);
      }
      return new Response(null, { status: 204, headers: cors });
    }

    try {
      const url = new URL(request.url);

      if (request.method === "GET" && url.pathname === "/health") {
        return json({ ok: true, service: "imdaderohani-live-chat-files" }, 200, cors);
      }

      if (!ALLOWED_ORIGINS.has(origin)) {
        return json({ ok: false, error: "ORIGIN_NOT_ALLOWED" }, 403, cors);
      }

      const user = await verifyFirebaseUser(request);
      if (!user) {
        return json({ ok: false, error: "UNAUTHORIZED" }, 401, cors);
      }

      if (request.method === "POST" && url.pathname === "/upload") {
        return await uploadFile(request, env, user, cors);
      }

      if (request.method === "GET" && url.pathname.startsWith("/file/")) {
        return await serveFile(request, env, user, url.pathname.slice(6), cors);
      }

      if (request.method === "DELETE" && url.pathname.startsWith("/file/")) {
        return await deleteFile(env, user, url.pathname.slice(6), cors);
      }

      return json({ ok: false, error: "NOT_FOUND" }, 404, cors);
    } catch (error) {
      console.error(JSON.stringify({ event: "worker_error", message: error?.message || String(error) }));
      return json({ ok: false, error: "SERVER_ERROR" }, 500, cors);
    }
  },
};

async function verifyFirebaseUser(request) {
  const authorization = request.headers.get("Authorization") || "";
  if (!authorization.startsWith("Bearer ")) return null;

  const idToken = authorization.slice(7).trim();
  if (!idToken) return null;

  const response = await fetch(
    `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${FIREBASE_API_KEY}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ idToken }),
    },
  );

  if (!response.ok) return null;
  const result = await response.json();
  const firebaseUser = result?.users?.[0];
  if (!firebaseUser?.localId || firebaseUser.disabled === true) return null;

  return { uid: firebaseUser.localId, isAdmin: firebaseUser.localId === ADMIN_UID };
}

async function uploadFile(request, env, user, cors) {
  if (!request.body) return json({ ok: false, error: "FILE_REQUIRED" }, 400, cors);

  const originalName = cleanFileName(decodeHeader(request.headers.get("X-File-Name") || "file"));
  const contentType = normalizeType(request.headers.get("Content-Type") || "");
  const claimedSize = Number(request.headers.get("X-File-Size") || 0);
  const contentLength = Number(request.headers.get("Content-Length") || 0);
  const rule = TYPE_RULES.get(contentType);

  if (!rule) return json({ ok: false, error: "FILE_TYPE_NOT_ALLOWED" }, 415, cors);
  if (!Number.isSafeInteger(claimedSize) || claimedSize <= 0) {
    return json({ ok: false, error: "FILE_SIZE_INVALID" }, 400, cors);
  }
  if (contentLength > 0 && contentLength !== claimedSize) {
    return json({ ok: false, error: "FILE_SIZE_MISMATCH" }, 400, cors);
  }
  if (claimedSize > rule.max) {
    return json({ ok: false, error: "FILE_TOO_LARGE", maxBytes: rule.max }, 413, cors);
  }

  const quota = await takeDailyQuota(env, user.uid, claimedSize);
  if (!quota.ok) return json({ ok: false, error: quota.error }, 429, cors);

  const now = new Date();
  const expiresAt = new Date(now.getTime() + RETENTION_DAYS * 86400000);
  const objectKey = `${user.uid}/${now.toISOString().slice(0, 10)}/${crypto.randomUUID()}-${originalName}`;

  try {
    const stored = await env.LIVE_CHAT_FILES.put(objectKey, request.body, {
      httpMetadata: {
        contentType,
        contentDisposition: `inline; filename="${asciiFileName(originalName)}"`,
        cacheControl: "private, no-store",
      },
      customMetadata: {
        ownerUid: user.uid,
        originalName,
        category: rule.category,
        size: String(claimedSize),
        uploadedAt: now.toISOString(),
        expiresAt: expiresAt.toISOString(),
      },
    });

    return json(
      {
        ok: true,
        attachment: {
          key: objectKey,
          name: originalName,
          type: contentType,
          category: rule.category,
          size: claimedSize,
          expiresAt: expiresAt.toISOString(),
          etag: stored.httpEtag,
        },
      },
      201,
      cors,
    );
  } catch (error) {
    await restoreDailyQuota(env, user.uid, claimedSize);
    throw error;
  }
}

async function serveFile(request, env, user, rawKey, cors) {
  const key = safeObjectKey(rawKey);
  if (!key) return json({ ok: false, error: "INVALID_FILE_KEY" }, 400, cors);

  const object = await env.LIVE_CHAT_FILES.get(key, { range: request.headers });
  if (!object) return json({ ok: false, error: "FILE_NOT_FOUND" }, 404, cors);

  const ownerUid = object.customMetadata?.ownerUid || key.split("/")[0];
  if (!user.isAdmin && ownerUid !== user.uid) {
    return json({ ok: false, error: "FILE_ACCESS_DENIED" }, 403, cors);
  }

  const headers = new Headers(cors);
  object.writeHttpMetadata(headers);
  headers.set("ETag", object.httpEtag);
  headers.set("Accept-Ranges", "bytes");
  headers.set("Cache-Control", "private, no-store");
  headers.set("X-Content-Type-Options", "nosniff");

  const originalName = object.customMetadata?.originalName || "attachment";
  headers.set("Content-Disposition", `inline; filename*=UTF-8''${encodeURIComponent(originalName)}`);

  let status = 200;
  if (object.range && typeof object.range.offset === "number" && typeof object.range.length === "number") {
    status = 206;
    const start = object.range.offset;
    const end = start + object.range.length - 1;
    headers.set("Content-Range", `bytes ${start}-${end}/${object.size}`);
    headers.set("Content-Length", String(object.range.length));
  } else {
    headers.set("Content-Length", String(object.size));
  }

  return new Response(object.body, { status, headers });
}

async function deleteFile(env, user, rawKey, cors) {
  const key = safeObjectKey(rawKey);
  if (!key) return json({ ok: false, error: "INVALID_FILE_KEY" }, 400, cors);

  const object = await env.LIVE_CHAT_FILES.head(key);
  if (!object) return json({ ok: false, error: "FILE_NOT_FOUND" }, 404, cors);

  const ownerUid = object.customMetadata?.ownerUid || key.split("/")[0];
  if (!user.isAdmin && ownerUid !== user.uid) {
    return json({ ok: false, error: "FILE_ACCESS_DENIED" }, 403, cors);
  }

  await env.LIVE_CHAT_FILES.delete(key);
  return json({ ok: true, deleted: true }, 200, cors);
}

async function takeDailyQuota(env, uid, bytes) {
  const day = new Date().toISOString().slice(0, 10);
  const key = `_limits/${uid}/${day}.json`;
  const currentObject = await env.LIVE_CHAT_FILES.get(key);
  let current = { files: 0, bytes: 0 };

  if (currentObject) {
    try {
      const parsed = await currentObject.json();
      current.files = Number(parsed.files || 0);
      current.bytes = Number(parsed.bytes || 0);
    } catch (error) {
      console.error(JSON.stringify({ event: "quota_parse_error", uid }));
    }
  }

  if (current.files + 1 > DAILY_FILE_LIMIT) return { ok: false, error: "DAILY_FILE_LIMIT" };
  if (current.bytes + bytes > DAILY_BYTE_LIMIT) return { ok: false, error: "DAILY_SIZE_LIMIT" };

  await env.LIVE_CHAT_FILES.put(
    key,
    JSON.stringify({ files: current.files + 1, bytes: current.bytes + bytes }),
    {
      httpMetadata: { contentType: "application/json", cacheControl: "private, no-store" },
      customMetadata: { ownerUid: uid, category: "quota", uploadedAt: new Date().toISOString() },
    },
  );

  return { ok: true };
}

async function restoreDailyQuota(env, uid, bytes) {
  try {
    const day = new Date().toISOString().slice(0, 10);
    const key = `_limits/${uid}/${day}.json`;
    const currentObject = await env.LIVE_CHAT_FILES.get(key);
    if (!currentObject) return;
    const current = await currentObject.json();
    await env.LIVE_CHAT_FILES.put(
      key,
      JSON.stringify({
        files: Math.max(0, Number(current.files || 0) - 1),
        bytes: Math.max(0, Number(current.bytes || 0) - bytes),
      }),
      { httpMetadata: { contentType: "application/json", cacheControl: "private, no-store" } },
    );
  } catch (error) {
    console.error(JSON.stringify({ event: "quota_restore_error", uid }));
  }
}

function safeObjectKey(rawKey) {
  try {
    const key = decodeURIComponent(rawKey);
    if (!key || key.startsWith("_") || key.includes("..") || key.includes("\\")) return "";
    return key;
  } catch (error) {
    return "";
  }
}

function cleanFileName(value) {
  const cleaned = value
    .normalize("NFKC")
    .replace(/[\\/:*?"<>|\u0000-\u001F]/g, "-")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^[-.]+|[-.]+$/g, "")
    .slice(0, 90);
  return cleaned || "attachment";
}

function asciiFileName(value) {
  return value.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 90) || "attachment";
}

function normalizeType(value) {
  return value.split(";")[0].trim().toLowerCase();
}

function decodeHeader(value) {
  try {
    return decodeURIComponent(value);
  } catch (error) {
    return value;
  }
}

function corsHeaders(origin) {
  const headers = new Headers({
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, Content-Type, X-File-Name, X-File-Size",
    "Access-Control-Expose-Headers": "Content-Length, Content-Range, Content-Disposition, ETag",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  });
  if (ALLOWED_ORIGINS.has(origin)) headers.set("Access-Control-Allow-Origin", origin);
  return headers;
}

function json(data, status, cors) {
  const headers = new Headers(cors);
  headers.set("Content-Type", "application/json; charset=UTF-8");
  headers.set("Cache-Control", "no-store");
  return new Response(JSON.stringify(data), { status, headers });
}
