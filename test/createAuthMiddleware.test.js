const assert = require("node:assert/strict");
const { afterEach, beforeEach, describe, test } = require("node:test");
const axios = require("axios");

const { createAuthMiddleware } = require("../src/createAuthMiddleware");

const originalEnv = {
  NODE_ENV: process.env.NODE_ENV,
  DEV_MODE: process.env.DEV_MODE,
};
const originalAxiosGet = axios.get;

function restoreEnv(name, value) {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

function createResponse() {
  return {
    statusCode: 200,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    },
  };
}

async function runMiddleware(middleware, authorization) {
  const req = { headers: {} };
  if (authorization) req.headers.authorization = authorization;
  const res = createResponse();
  let nextCalled = false;

  await middleware(req, res, () => {
    nextCalled = true;
  });

  return { req, res, nextCalled };
}

describe("createAuthMiddleware dev bypass safety", () => {
  beforeEach(() => {
    axios.get = originalAxiosGet;
    delete process.env.NODE_ENV;
    delete process.env.DEV_MODE;
  });

  afterEach(() => {
    axios.get = originalAxiosGet;
    restoreEnv("NODE_ENV", originalEnv.NODE_ENV);
    restoreEnv("DEV_MODE", originalEnv.DEV_MODE);
  });

  test("blocks a custom bypass in production", async () => {
    process.env.NODE_ENV = "production";
    process.env.DEV_MODE = "true";
    let axiosCalled = false;
    axios.get = async () => {
      axiosCalled = true;
      throw new Error("axios must not run without a token");
    };
    const errors = [];
    const middleware = createAuthMiddleware({
      authApiUrl: "http://auth.test",
      devBypass: () => true,
      logger: { error: (message) => errors.push(message) },
    });

    const result = await runMiddleware(middleware);

    assert.equal(result.nextCalled, false);
    assert.equal(result.res.statusCode, 401);
    assert.deepEqual(result.res.body, { error: "Unauthorized" });
    assert.equal(axiosCalled, false);
    assert.equal(errors.length, 1);
  });

  test("blocks a custom bypass when NODE_ENV is unset", async () => {
    process.env.DEV_MODE = "true";
    const middleware = createAuthMiddleware({
      authApiUrl: "http://auth.test",
      devBypass: () => true,
      logger: { error: () => {} },
    });

    const result = await runMiddleware(middleware);

    assert.equal(result.nextCalled, false);
    assert.equal(result.res.statusCode, 401);
  });

  test("allows the default bypass only in explicit development mode", async () => {
    process.env.NODE_ENV = "development";
    process.env.DEV_MODE = "true";
    const middleware = createAuthMiddleware({ authApiUrl: "http://auth.test" });

    const result = await runMiddleware(middleware);

    assert.equal(result.nextCalled, true);
    assert.equal(result.req.user.role, "admin");
  });

  test("respects a false custom bypass in development", async () => {
    process.env.NODE_ENV = "development";
    process.env.DEV_MODE = "true";
    const middleware = createAuthMiddleware({
      authApiUrl: "http://auth.test",
      devBypass: () => false,
    });

    const result = await runMiddleware(middleware);

    assert.equal(result.nextCalled, false);
    assert.equal(result.res.statusCode, 401);
  });

  test("uses remote verification in production even when custom bypass returns true", async () => {
    process.env.NODE_ENV = "production";
    axios.get = async () => ({ data: { id: "remote-user", role: "user" } });
    const middleware = createAuthMiddleware({
      authApiUrl: "http://auth.test",
      devBypass: () => true,
    });

    const result = await runMiddleware(middleware, "Bearer valid-token");

    assert.equal(result.nextCalled, true);
    assert.deepEqual(result.req.user, { id: "remote-user", role: "user" });
  });
});

describe("createAuthMiddleware app authorization", () => {
  beforeEach(() => {
    process.env.NODE_ENV = "production";
    delete process.env.DEV_MODE;
    axios.get = originalAxiosGet;
  });

  afterEach(() => {
    axios.get = originalAxiosGet;
    restoreEnv("NODE_ENV", originalEnv.NODE_ENV);
    restoreEnv("DEV_MODE", originalEnv.DEV_MODE);
  });

  test("rejects an explicitly empty appAccessKey", () => {
    assert.throws(
      () => createAuthMiddleware({ authApiUrl: "http://auth.test", appAccessKey: "  " }),
      /appAccessKey.*neprázdný string/
    );
  });

  test("allows a user whose allowedApps contain the required app", async () => {
    axios.get = async () => ({
      data: { id: "allowed-user", allowedApps: ["calendar", "production"] },
    });
    const middleware = createAuthMiddleware({
      authApiUrl: "http://auth.test",
      appAccessKey: "calendar",
    });

    const result = await runMiddleware(middleware, "Bearer valid-token");

    assert.equal(result.nextCalled, true);
    assert.equal(result.res.statusCode, 200);
  });

  test("keeps null allowedApps as access to all applications", async () => {
    axios.get = async () => ({ data: { id: "admin-user", allowedApps: null } });
    const middleware = createAuthMiddleware({
      authApiUrl: "http://auth.test",
      appAccessKey: "calendar",
    });

    const result = await runMiddleware(middleware, "Bearer valid-token");

    assert.equal(result.nextCalled, true);
  });

  test("denies a user whose allowedApps do not contain the required app", async () => {
    axios.get = async () => ({ data: { id: "denied-user", allowedApps: ["production"] } });
    const middleware = createAuthMiddleware({
      authApiUrl: "http://auth.test",
      appAccessKey: "calendar",
    });

    const result = await runMiddleware(middleware, "Bearer valid-token");

    assert.equal(result.nextCalled, false);
    assert.equal(result.res.statusCode, 403);
    assert.deepEqual(result.res.body, { error: "Forbidden" });
  });

  test("fails closed for a malformed allowedApps claim", async () => {
    axios.get = async () => ({ data: { id: "malformed-user", allowedApps: "calendar" } });
    const middleware = createAuthMiddleware({
      authApiUrl: "http://auth.test",
      appAccessKey: "calendar",
    });

    const result = await runMiddleware(middleware, "Bearer valid-token");

    assert.equal(result.nextCalled, false);
    assert.equal(result.res.statusCode, 403);
  });

  test("accepts the legacy allowed_apps claim name", async () => {
    axios.get = async () => ({ data: { id: "legacy-user", allowed_apps: ["calendar"] } });
    const middleware = createAuthMiddleware({
      authApiUrl: "http://auth.test",
      appAccessKey: "calendar",
    });

    const result = await runMiddleware(middleware, "Bearer valid-token");

    assert.equal(result.nextCalled, true);
  });

  test("applies app authorization to a development bypass user", async () => {
    process.env.NODE_ENV = "development";
    process.env.DEV_MODE = "true";
    const middleware = createAuthMiddleware({
      authApiUrl: "http://auth.test",
      appAccessKey: "calendar",
      devUser: { id: "dev-user", role: "admin", allowedApps: ["production"] },
    });

    const result = await runMiddleware(middleware);

    assert.equal(result.nextCalled, false);
    assert.equal(result.res.statusCode, 403);
  });
});
