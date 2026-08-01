/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  swcMinify: true,

  // API proxy to backend services
  async rewrites() {
    const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
    return [
      { source: "/api/auth/:path*",   destination: `${API}/auth/:path*` },
      { source: "/api/logs/:path*",   destination: `${API}/logs/:path*` },
      { source: "/api/alerts/:path*", destination: `${API}/alerts/:path*` },
      { source: "/api/ai/:path*",     destination: `${API}/ai/:path*` },
      { source: "/api/soar/:path*",   destination: `${API}/soar/:path*` },
      { source: "/api/intel/:path*",  destination: `${API}/intel/:path*` },
      { source: "/api/reports/:path*",destination: `${API}/reports/:path*` },
      { source: "/api/vpn/:path*",    destination: `${API}/vpn/:path*` },
      { source: "/api/cloud/:path*",  destination: `${API}/cloud/:path*` },
      { source: "/api/agents/:path*", destination: `${API.replace(':8000',':8014')}/agents/:path*` },
    ];
  },

  // Allow images from any domain in threat intel
  images: {
    remotePatterns: [
      { protocol: "https", hostname: "**" },
      { protocol: "http",  hostname: "**" },
    ],
  },

  // Environment variables exposed to browser
  env: {
    NEXT_PUBLIC_API_URL:  process.env.NEXT_PUBLIC_API_URL  || "http://localhost:8000",
    NEXT_PUBLIC_WS_URL:   process.env.NEXT_PUBLIC_WS_URL   || "ws://localhost:8000",
    NEXT_PUBLIC_APP_NAME: process.env.NEXT_PUBLIC_APP_NAME || "SentinelAI",
  },

  // Build output for local deployment
  output: "standalone",
};

module.exports = nextConfig;
