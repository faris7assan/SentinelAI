// ─── _app.jsx ─ Global app wrapper ───────────────────────────
import Head from "next/head";

export default function MyApp({ Component, pageProps }) {
  return (
    <>
      <Head>
        <title>SentinelAI — Autonomous SOC Platform</title>
        <meta name="description" content="Enterprise-grade AI-powered Security Operations Center" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="icon" href="/favicon.ico" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap"
          rel="stylesheet"
        />
      </Head>
      <style jsx global>{`
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        html { font-size: 14px; }
        body {
          font-family: 'Inter', system-ui, -apple-system, sans-serif;
          background: #070B14;
          color: #E2E8FF;
          -webkit-font-smoothing: antialiased;
        }
        code, pre, .mono { font-family: 'JetBrains Mono', 'Fira Code', monospace; }
        ::-webkit-scrollbar { width: 5px; height: 5px; }
        ::-webkit-scrollbar-track { background: #0A0E1A; }
        ::-webkit-scrollbar-thumb { background: #1E2C4A; border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: #00D4FF44; }
        ::selection { background: #00D4FF33; color: #E2E8FF; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
        @keyframes spin  { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        @keyframes slideIn { from { transform: translateY(-8px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
        @keyframes glow {
          0%, 100% { box-shadow: 0 0 5px #00D4FF44; }
          50%       { box-shadow: 0 0 20px #00D4FF88; }
        }
        input[type="text"], input[type="password"], input[type="email"], textarea {
          background: #0D1424 !important;
          color: #E2E8FF !important;
          border: 1px solid #1E2C4A !important;
          outline: none;
        }
        input::placeholder, textarea::placeholder { color: #2A3555 !important; }
        button { font-family: inherit; }
        a { color: #00D4FF; text-decoration: none; }
        a:hover { text-decoration: underline; }
      `}</style>
      <Component {...pageProps} />
    </>
  );
}
