// src/createAuthMiddleware.js
const axios = require("axios");

/**
 * Vytvoří univerzální Express middleware pro ověřování uživatele přes auth-app.
 *
 * Options:
 *  - authApiUrl (string, povinné) – např. "http://auth-backend:5000"
 *  - devBypass (function | undefined) – doplňková podmínka pro bypass.
 *        Bypass je vždy povolen pouze při NODE_ENV === "development".
 *        Bez callbacku se navíc vyžaduje DEV_MODE === "true".
 *  - devUser (object | undefined) – co se dá do req.user v DEV režimu
 *  - appAccessKey (string, povinné) – klíč aplikace vyžadovaný v allowedApps
 *  - timeoutMs (number | undefined) – timeout HTTP požadavku, default 5000
 *  - logger (object | undefined) – { info, error } – volitelné logování
 */
function createAuthMiddleware(options = {}) {
  const {
    authApiUrl,
    devBypass,
    devUser,
    appAccessKey,
    timeoutMs = 5000,
    logger = console,
  } = options;

  if (!authApiUrl) {
    throw new Error("createAuthMiddleware: 'authApiUrl' je povinné.");
  }

  const requiredApp = typeof appAccessKey === "string" ? appAccessKey.trim() : "";
  if (!requiredApp) {
    throw new Error("createAuthMiddleware: 'appAccessKey' je povinný neprázdný string.");
  }

  let blockedBypassLogged = false;

  const isDevBypass = (req) => {
    const nodeEnv = String(process.env.NODE_ENV || "").trim().toLowerCase();
    const isDevelopment = nodeEnv === "development";
    const devMode = String(process.env.DEV_MODE || "").trim().toLowerCase() === "true";

    // Bezpečnostní hranice musí zůstat uvnitř shared knihovny. Vlastní callback
    // proto nikdy nesmí zapnout bypass mimo explicitní development prostředí.
    if (!isDevelopment) {
      if (devMode && !blockedBypassLogged) {
        logger.error(
          `DEV_MODE=true při NODE_ENV=${nodeEnv || "<unset>"} — auth bypass je zakázán.`
        );
        blockedBypassLogged = true;
      }
      return false;
    }

    if (typeof devBypass === "function") {
      return devBypass(req) === true;
    }
    return devMode;
  };

  const effectiveDevUser =
    devUser || { id: "dev-user", role: "admin", status: "active" };

  const continueIfAppAllowed = (req, res, next) => {
    const allowedApps = req.user?.allowedApps ?? req.user?.allowed_apps;
    if (allowedApps == null) return next();

    // Podepsaný claim s neočekávaným typem nesmí omylem znamenat plný přístup.
    if (!Array.isArray(allowedApps) || !allowedApps.includes(requiredApp)) {
      return res.status(403).json({ error: "Forbidden" });
    }
    return next();
  };

  return async function authMiddleware(req, res, next) {
    try {
      // 1) DEV bypass
      if (isDevBypass(req)) {
        req.user = effectiveDevUser;
        return continueIfAppAllowed(req, res, next);
      }

      // 2) Token z hlavičky
      const token = req.headers.authorization;
      if (typeof token !== "string" || !/^Bearer\s+\S+$/i.test(token.trim())) {
        return res.status(401).json({ error: "Unauthorized" });
      }

      const verifyUrl = `${authApiUrl.replace(/\/+$/, "")}/api/auth/verify`;

      // 3) Ověření tokenu u auth-app
      const response = await axios.get(verifyUrl, {
        headers: { Authorization: token },
        timeout: timeoutMs,
      });

      // Neplatný upstream kontrakt je nedostupná autentizační služba, ne
      // neplatný klientský token. Klient tak může bezpečně odlišit retry stav.
      if (!response.data || typeof response.data !== "object" || Array.isArray(response.data)) {
        throw new Error("Auth service returned an invalid user payload");
      }

      req.user = response.data;
      return continueIfAppAllowed(req, res, next);
    } catch (err) {
      const upstreamStatus = Number(err.response?.status);
      if (upstreamStatus === 401) {
        return res.status(401).json({ error: "Unauthorized" });
      }
      if (upstreamStatus === 403) {
        return res.status(403).json({ error: "Forbidden" });
      }

      logger.error("Auth service unavailable:", err.message);
      return res.status(503).json({ error: "Authentication service unavailable" });
    }
  };
}

module.exports = {
  createAuthMiddleware,
};
