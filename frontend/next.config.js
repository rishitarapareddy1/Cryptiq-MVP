/** @type {import('next').NextConfig} */
const API_URL = process.env.CRYPTIQ_API_URL || "http://127.0.0.1:8000";

// These are ONLY backend API routes — no Next.js page exists at these paths
const API_ONLY_PREFIXES = [
  "/scan",
  "/discover",
  "/scans",
  "/aws",
  "/workspace",  // back here — pure API
  "/audit-log",
  "/health",
  "/docs",
  "/redoc",
  "/openapi.json",
];

const PAGE_AND_API_PREFIXES = [
  "/ssh",
  "/migrate",
];

const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return {
      beforeFiles: [
        // API-only: rewrite both exact and sub-paths
        ...API_ONLY_PREFIXES.map((prefix) => ({
          source: `${prefix}/:path*`,
          destination: `${API_URL}${prefix}/:path*`,
        })),
        ...API_ONLY_PREFIXES.map((prefix) => ({
          source: prefix,
          destination: `${API_URL}${prefix}`,
        })),
        // Page+API: only rewrite sub-paths, leave bare path for Next.js to serve
        ...PAGE_AND_API_PREFIXES.map((prefix) => ({
          source: `${prefix}/:path+`,
          destination: `${API_URL}${prefix}/:path+`,
        })),
      ],
    };
  },
};

module.exports = nextConfig;