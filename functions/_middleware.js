/*
 * Cloudflare Pages shared-login middleware
 *
 * Required Cloudflare Secrets:
 *   AUTH_USERNAME
 *   AUTH_PASSWORD
 *   SESSION_SECRET
 *
 * File location:
 *   functions/_middleware.js
 */

const COOKIE_NAME = "phgis_session";

// Login remains valid for 8 hours.
const SESSION_SECONDS = 60 * 60 * 8;

const encoder = new TextEncoder();


/* =========================================================
   HTML SAFETY
   ========================================================= */

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}


/*
 * Only allow redirects to locations inside this same website.
 */
function safeNext(value) {
  if (
    typeof value !== "string" ||
    !value.startsWith("/") ||
    value.startsWith("//")
  ) {
    return "/";
  }

  return value;
}


/* =========================================================
   LOGIN PAGE
   ========================================================= */

function loginPage(next = "/", error = "") {
  const safeRedirect = escapeHtml(safeNext(next));

  const errorMessage = error
    ? `
      <div class="error" role="alert">
        ${escapeHtml(error)}
      </div>
    `
    : "";

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">

  <meta
    name="viewport"
    content="width=device-width, initial-scale=1"
  >

  <title>Private GIS Site</title>

  <style>
    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;

      background: #f5f7fa;

      font-family:
        Arial,
        Helvetica,
        sans-serif;

      color: #1f2937;
    }

    .login-card {
      width: 100%;
      max-width: 430px;

      background: #ffffff;

      border: 1px solid #d1d5db;
      border-radius: 12px;

      padding: 32px;

      box-shadow:
        0 10px 30px rgba(0, 0, 0, 0.08);
    }

    h1 {
      margin: 0 0 10px 0;

      font-size: 27px;
      line-height: 1.2;
    }

    .subtitle {
      margin: 0 0 24px 0;

      color: #6b7280;

      line-height: 1.5;
    }

    label {
      display: block;

      margin-top: 17px;
      margin-bottom: 7px;

      font-weight: 600;
    }

    input {
      width: 100%;

      padding: 12px 13px;

      border: 1px solid #9ca3af;
      border-radius: 7px;

      background: white;

      color: #111827;

      font-size: 16px;
    }

    input:focus {
      outline: 2px solid #2563eb;
      outline-offset: 2px;
    }

    button {
      width: 100%;

      margin-top: 24px;

      padding: 13px;

      border: 0;
      border-radius: 7px;

      background: #2563eb;
      color: white;

      font-size: 16px;
      font-weight: 600;

      cursor: pointer;
    }

    button:hover {
      background: #1d4ed8;
    }

    button:focus {
      outline: 2px solid #111827;
      outline-offset: 2px;
    }

    .error {
      margin-bottom: 18px;

      padding: 11px 12px;

      border: 1px solid #fecaca;
      border-radius: 7px;

      background: #fef2f2;
      color: #991b1b;

      line-height: 1.4;
    }

    .notice {
      margin-top: 22px;
      margin-bottom: 0;

      color: #6b7280;

      font-size: 13px;
      line-height: 1.5;
    }
  </style>
</head>

<body>

  <main class="login-card">

    <h1>Private GIS Site</h1>

    <p class="subtitle">
      Enter the authorized username and password to continue.
    </p>

    ${errorMessage}

    <form method="POST" action="/__auth/login">

      <input
        type="hidden"
        name="next"
        value="${safeRedirect}"
      >

      <label for="username">
        Username
      </label>

      <input
        id="username"
        name="username"
        type="text"
        autocomplete="username"
        required
        autofocus
      >

      <label for="password">
        Password
      </label>

      <input
        id="password"
        name="password"
        type="password"
        autocomplete="current-password"
        required
      >

      <button type="submit">
        Sign in
      </button>

    </form>

    <p class="notice">
      Access is restricted to authorized users.
    </p>

  </main>

</body>
</html>`;
}


/* =========================================================
   HTTP HEADERS FOR LOGIN PAGE
   ========================================================= */

function loginHeaders() {
  return {
    "Content-Type": "text/html; charset=UTF-8",

    "Cache-Control":
      "no-store, no-cache, must-revalidate, private",

    "Pragma": "no-cache",

    "Expires": "0",

    "X-Content-Type-Options": "nosniff",

    "Referrer-Policy": "no-referrer",

    "X-Frame-Options": "DENY",

    "Content-Security-Policy":
      "default-src 'none'; " +
      "style-src 'unsafe-inline'; " +
      "form-action 'self'; " +
      "base-uri 'none'; " +
      "frame-ancestors 'none'"
  };
}


/* =========================================================
   COOKIE READER
   ========================================================= */

function getCookie(request, name) {
  const cookieHeader =
    request.headers.get("Cookie");

  if (!cookieHeader) {
    return null;
  }

  const cookies =
    cookieHeader.split(";");

  for (const cookie of cookies) {
    const separator =
      cookie.indexOf("=");

    if (separator === -1) {
      continue;
    }

    const key =
      cookie
        .substring(0, separator)
        .trim();

    const value =
      cookie
        .substring(separator + 1)
        .trim();

    if (key === name) {
      return value;
    }
  }

  return null;
}


/* =========================================================
   BASE64 URL HELPERS
   ========================================================= */

function bytesToBase64Url(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary +=
      String.fromCharCode(byte);
  }

  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}


function base64UrlToBytes(value) {
  let base64 =
    value
      .replaceAll("-", "+")
      .replaceAll("_", "/");

  while (base64.length % 4 !== 0) {
    base64 += "=";
  }

  const binary =
    atob(base64);

  const bytes =
    new Uint8Array(binary.length);

  for (
    let i = 0;
    i < binary.length;
    i++
  ) {
    bytes[i] =
      binary.charCodeAt(i);
  }

  return bytes;
}


/* =========================================================
   HMAC SIGNING
   ========================================================= */

async function getSigningKey(secret) {
  return crypto.subtle.importKey(
    "raw",

    encoder.encode(secret),

    {
      name: "HMAC",
      hash: "SHA-256"
    },

    false,

    ["sign", "verify"]
  );
}


async function signValue(value, secret) {
  const key =
    await getSigningKey(secret);

  const signature =
    await crypto.subtle.sign(
      "HMAC",
      key,
      encoder.encode(value)
    );

  return bytesToBase64Url(
    new Uint8Array(signature)
  );
}


async function verifySignature(
  value,
  signature,
  secret
) {
  try {
    const key =
      await getSigningKey(secret);

    return await crypto.subtle.verify(
      "HMAC",
      key,
      base64UrlToBytes(signature),
      encoder.encode(value)
    );
  } catch {
    return false;
  }
}


/* =========================================================
   CREATE LOGIN SESSION
   ========================================================= */

async function createSession(secret) {
  const expires =
    Math.floor(Date.now() / 1000)
    + SESSION_SECONDS;

  const payload =
    String(expires);

  const signature =
    await signValue(
      payload,
      secret
    );

  return `${payload}.${signature}`;
}


/* =========================================================
   VALIDATE LOGIN SESSION
   ========================================================= */

async function validSession(
  token,
  secret
) {
  if (!token) {
    return false;
  }

  const parts =
    token.split(".");

  if (parts.length !== 2) {
    return false;
  }

  const [
    expiresText,
    signature
  ] = parts;

  const expires =
    Number(expiresText);

  if (!Number.isFinite(expires)) {
    return false;
  }

  const now =
    Math.floor(Date.now() / 1000);

  if (expires <= now) {
    return false;
  }

  return verifySignature(
    expiresText,
    signature,
    secret
  );
}


/* =========================================================
   MAIN CLOUDFLARE PAGES MIDDLEWARE
   ========================================================= */

export async function onRequest(context) {

  const {
    request,
    env
  } = context;

  const url =
    new URL(request.url);


  /*
   * -------------------------------------------------------
   * VERSION TEST
   *
   * This lets us confirm that Cloudflare is actually
   * running THIS middleware file.
   *
   * Visit:
   *
   * /__auth/version
   *
   * -------------------------------------------------------
   */

  if (
    url.pathname ===
    "/__auth/version"
  ) {
    return new Response(
      "PHGIS LOGIN MIDDLEWARE V3",
      {
        status: 200,

        headers: {
          "Content-Type":
            "text/plain; charset=UTF-8",

          "Cache-Control":
            "no-store"
        }
      }
    );
  }


  /*
   * -------------------------------------------------------
   * VERIFY REQUIRED CLOUDFLARE SECRETS
   * -------------------------------------------------------
   */

  if (
    !env.AUTH_USERNAME ||
    !env.AUTH_PASSWORD ||
    !env.SESSION_SECRET
  ) {
    return new Response(
      "Authentication configuration is incomplete.",
      {
        status: 500,

        headers: {
          "Content-Type":
            "text/plain; charset=UTF-8",

          "Cache-Control":
            "no-store"
        }
      }
    );
  }


  /*
   * -------------------------------------------------------
   * LOGIN FORM SUBMISSION
   * -------------------------------------------------------
   */

  if (
    url.pathname ===
      "/__auth/login" &&
    request.method ===
      "POST"
  ) {

    const form =
      await request.formData();

    const username =
      String(
        form.get("username") || ""
      ).trim();

    const password =
      String(
        form.get("password") || ""
      );

    const next =
      safeNext(
        String(
          form.get("next") || "/"
        )
      );


    /*
     * Incorrect username/password.
     */

    if (
      username !==
        env.AUTH_USERNAME ||
      password !==
        env.AUTH_PASSWORD
    ) {
      return new Response(
        loginPage(
          next,
          "The username or password is incorrect."
        ),
        {
          /*
           * Deliberately return 200 here.
           *
           * We do NOT want Edge to interpret this as
           * HTTP Basic Authentication.
           */
          status: 200,

          headers:
            loginHeaders()
        }
      );
    }


    /*
     * Correct username/password.
     *
     * Create signed session cookie.
     */

    const session =
      await createSession(
        env.SESSION_SECRET
      );

    const headers =
      new Headers();

    headers.set(
      "Location",
      next
    );

    headers.append(
      "Set-Cookie",

      `${COOKIE_NAME}=${session}; ` +
      `Path=/; ` +
      `HttpOnly; ` +
      `Secure; ` +
      `SameSite=Strict; ` +
      `Max-Age=${SESSION_SECONDS}`
    );

    headers.set(
      "Cache-Control",
      "no-store"
    );


    /*
     * Redirect back to requested page.
     */

    return new Response(
      null,
      {
        status: 303,
        headers
      }
    );
  }


  /*
   * -------------------------------------------------------
   * LOG OUT
   *
   * Visit:
   *
   * /__auth/logout
   *
   * -------------------------------------------------------
   */

  if (
    url.pathname ===
    "/__auth/logout"
  ) {

    const headers =
      new Headers();

    headers.set(
      "Location",
      "/"
    );

    headers.append(
      "Set-Cookie",

      `${COOKIE_NAME}=; ` +
      `Path=/; ` +
      `HttpOnly; ` +
      `Secure; ` +
      `SameSite=Strict; ` +
      `Max-Age=0`
    );

    headers.set(
      "Cache-Control",
      "no-store"
    );

    return new Response(
      null,
      {
        status: 303,
        headers
      }
    );
  }


  /*
   * -------------------------------------------------------
   * CHECK FOR VALID LOGIN SESSION
   * -------------------------------------------------------
   */

  const session =
    getCookie(
      request,
      COOKIE_NAME
    );

  const isLoggedIn =
    await validSession(
      session,
      env.SESSION_SECRET
    );


  /*
   * -------------------------------------------------------
   * AUTHENTICATED
   *
   * Allow request to continue to:
   *
   * index.html
   * JavaScript
   * CSS
   * GeoJSON
   * JSON
   * CSV
   * images
   * etc.
   * -------------------------------------------------------
   */

  if (isLoggedIn) {

    const response =
      await context.next();

    /*
     * Avoid storing protected content in a browser/shared
     * cache after authentication.
     */

    const protectedResponse =
      new Response(
        response.body,
        response
      );

    protectedResponse.headers.set(
      "Cache-Control",
      "private, no-store"
    );

    protectedResponse.headers.set(
      "X-Content-Type-Options",
      "nosniff"
    );

    return protectedResponse;
  }


  /*
   * -------------------------------------------------------
   * NOT AUTHENTICATED
   *
   * Display our own HTML login page.
   *
   * IMPORTANT:
   * There is NO WWW-Authenticate header here.
   * Therefore Edge should NOT try to display its native
   * Basic Authentication dialog.
   * -------------------------------------------------------
   */

  const next =
    safeNext(
      url.pathname +
      url.search
    );

  return new Response(
    loginPage(next),
    {
      status: 200,
      headers:
        loginHeaders()
    }
  );
}