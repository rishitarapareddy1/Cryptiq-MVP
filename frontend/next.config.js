/** @type {import('next').NextConfig} */

// All Cryptiq API routes live on the FastAPI service (api.py). We never
// reimplement scanning/migration logic in JS — every data call below is
// proxied straight through to that backend untouched.
const API_URL = process.env.CRYPTIQ_API_URL || "http://127.0.0.1:8000";

const API_PREFIXES = [
  "/scan",
  "/discover",
  "/scans",
  "/aws",
  "/workspace",
  "/ssh",
  "/migrate",
  "/audit-log",
  "/health",
  "/docs",
  "/redoc",
  "/openapi.json",
];

const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return API_PREFIXES.map((prefix) => ({
      source: `${prefix}/:path*`,
      destination: `${API_URL}${prefix}/:path*`,
    })).concat(
      API_PREFIXES.map((prefix) => ({
        source: prefix,
        destination: `${API_URL}${prefix}`,
      }))
    );
  },
};

module.exports = nextConfig;