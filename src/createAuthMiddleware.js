// src/createAuthMiddleware.js
const axios = require("axios");

/**
 * Vytvoří univerzální Express middleware pro ověřování uživatele přes auth-app.
 *
 * Options:
 *  - authApiUrl (string, povinné) – např. "http://auth-backend:5000"
 *  - devBypass (function | undefined) – funkce (req) => boolean, default:
 *        NODE_ENV === "development" || DEV_MODE === "true"
 *  - devUser (object | undefined) – co se dá do req.user v DEV režimu
 *  - timeoutMs (number | undefined) – timeout HTTP požadavku, default 5000
 *  - logger (object | undefined) – { info, error } – volitelné logování
 */
function createAuthMiddleware(options = {}) {
  const {
    authApiUrl,
    devBypass,
    devUser,
    timeoutMs = 5000,
    logger = console,
  } = options;

  if (!authApiUrl) {
    throw new Error("createAuthMiddleware: 'authApiUrl' je povinné.");
  }

  const isDevBypass = (req) => {
    if (typeof devBypass === "function") {
      return devBypass(req);
    }
    const isDev = process.env.NODE_ENV === "development";
    const devMode = process.env.DEV_MODE === "true";
    if (process.env.NODE_ENV === "production" && devMode) {
      logger.error("DEV_MODE=true v produkci — auth bypass je zakázán.");
      return false;
    }
    return isDev && devMode;
  };

  const effectiveDevUser =
    devUser || { id: "dev-user", role: "admin", status: "active" };

  return async function authMiddleware(req, res, next) {
    try {
      // 1) DEV bypass
      if (isDevBypass(req)) {
        req.user = effectiveDevUser;
        return next();
      }

      // 2) Token z hlavičky
      const token = req.headers.authorization;
      if (!token) {
        return res.status(401).json({ error: "Unauthorized" });
      }

      const verifyUrl = `${authApiUrl.replace(/\/+$/, "")}/api/auth/verify`;

      // 3) Ověření tokenu u auth-app
      const response = await axios.get(verifyUrl, {
        headers: { Authorization: token },
        timeout: timeoutMs,
      });

      // očekáváme, že auth-app vrací payload usera v body
      req.user = response.data;
      return next();
    } catch (err) {
      logger.error("Auth error při ověřování tokenu:", err.message);
      if (process.env.NODE_ENV !== "production" && err.response && err.response.data) {
        logger.error("Response data:", err.response.data);
      }
      return res.status(401).json({ error: "Invalid token" });
    }
  };
}

module.exports = {
  createAuthMiddleware,
};
