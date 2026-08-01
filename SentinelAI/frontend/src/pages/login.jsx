/**
 * SentinelAI — Login Page
 * JWT login + TOTP MFA + OAuth2 SSO (Google/GitHub/Microsoft)
 */
import { useState, useEffect } from "react";
import { AuthAPI } from "../utils/api";

export default function LoginPage() {
  const [step, setStep]           = useState("credentials"); // credentials | mfa
  const [username, setUsername]   = useState("");
  const [password, setPassword]   = useState("");
  const [mfaToken, setMfaToken]   = useState("");
  const [loading, setLoading]     = useState(false);
  const [error, setError]         = useState("");
  const [providers, setProviders] = useState([]);
  const [showPass, setShowPass]   = useState(false);

  useEffect(() => {
    // Check if already logged in
    if (typeof window !== "undefined") {
      const token = localStorage.getItem("sentinelai_token");
      if (token) window.location.href = "/";
    }
    // Load OAuth2 providers
    AuthAPI.listOAuth2Providers?.()
      .then(d => setProviders(d?.providers || []))
      .catch(() => {});
  }, []);

  const handleLogin = async (e) => {
    e?.preventDefault();
    setLoading(true);
    setError("");
    try {
      const resp = await AuthAPI.login(username, password, step === "mfa" ? mfaToken : undefined);
      if (resp.detail === "MFA_REQUIRED") {
        setStep("mfa");
        setLoading(false);
        return;
      }
      localStorage.setItem("sentinelai_token",   resp.access_token);
      localStorage.setItem("sentinelai_refresh",  resp.refresh_token);
      localStorage.setItem("sentinelai_user",     JSON.stringify(resp.user));
      window.location.href = "/";
    } catch (err) {
      setError(err.message || "Login failed — check credentials");
      if (step === "mfa") setMfaToken("");
    }
    setLoading(false);
  };

  const PROVIDER_ICONS  = { google: "🔵 Google", github: "⚫ GitHub", microsoft: "🟦 Microsoft" };
  const PROVIDER_COLORS = { google: "#4285F4",   github: "#24292E",   microsoft: "#0078D4"     };

  return (
    <div style={{
      minHeight: "100vh", background: "radial-gradient(ellipse at top, #0D1835 0%, #070B14 60%)",
      display: "flex", alignItems: "center", justifyContent: "center",
      fontFamily: "'Inter', system-ui, sans-serif",
    }}>
      {/* Background grid */}
      <div style={{
        position: "fixed", inset: 0, zIndex: 0,
        backgroundImage: "linear-gradient(#1A2540 1px, transparent 1px), linear-gradient(90deg, #1A2540 1px, transparent 1px)",
        backgroundSize: "40px 40px", opacity: 0.3,
      }}/>

      <div style={{ position: "relative", zIndex: 1, width: "100%", maxWidth: 420, padding: "0 20px" }}>

        {/* Logo */}
        <div style={{ textAlign: "center", marginBottom: 32 }}>
          <div style={{
            width: 64, height: 64, borderRadius: "50%", margin: "0 auto 16px",
            background: "linear-gradient(135deg, #00D4FF22, #0050FF22)",
            border: "2px solid #00D4FF44",
            display: "flex", alignItems: "center", justifyContent: "center", fontSize: 30,
            boxShadow: "0 0 30px #00D4FF22",
          }}>🛡️</div>
          <h1 style={{ color: "#E2E8FF", fontSize: 26, fontWeight: 800, margin: 0, letterSpacing: -0.5 }}>
            SentinelAI
          </h1>
          <p style={{ color: "#4A5578", fontSize: 13, margin: "6px 0 0" }}>
            Autonomous Security Operations Platform
          </p>
        </div>

        {/* Card */}
        <div style={{
          background: "rgba(13,20,36,0.95)", border: "1px solid #1E2C4A",
          borderRadius: 16, padding: 32,
          boxShadow: "0 20px 60px rgba(0,0,0,0.5), 0 0 0 1px rgba(0,212,255,0.05)",
        }}>

          {/* Step indicator */}
          {step === "mfa" && (
            <div style={{
              background: "#00D4FF11", border: "1px solid #00D4FF33",
              borderRadius: 8, padding: "10px 14px", marginBottom: 20,
              display: "flex", alignItems: "center", gap: 8,
            }}>
              <span style={{ fontSize: 18 }}>🔐</span>
              <div>
                <div style={{ color: "#00D4FF", fontSize: 13, fontWeight: 600 }}>MFA Required</div>
                <div style={{ color: "#6B7DB3", fontSize: 11 }}>Enter the 6-digit code from your authenticator app</div>
              </div>
            </div>
          )}

          {/* Error */}
          {error && (
            <div style={{
              background: "#FF3B3B11", border: "1px solid #FF3B3B33",
              borderRadius: 8, padding: "10px 14px", marginBottom: 20,
              display: "flex", alignItems: "center", gap: 8,
            }}>
              <span>⚠️</span>
              <span style={{ color: "#FF8080", fontSize: 13 }}>{error}</span>
            </div>
          )}

          <form onSubmit={handleLogin}>
            {step === "credentials" && (
              <>
                {/* Username */}
                <div style={{ marginBottom: 16 }}>
                  <label style={{ color: "#6B7DB3", fontSize: 12, fontWeight: 500, display: "block", marginBottom: 6, textTransform: "uppercase", letterSpacing: 0.5 }}>
                    Username
                  </label>
                  <input
                    type="text" value={username} onChange={e => setUsername(e.target.value)}
                    placeholder="analyst1" required autoFocus
                    style={{
                      width: "100%", padding: "11px 14px", borderRadius: 8,
                      background: "#0A0E1A", border: "1px solid #1E2C4A",
                      color: "#E2E8FF", fontSize: 14, outline: "none",
                      transition: "border-color 0.15s",
                    }}
                    onFocus={e => e.target.style.borderColor = "#00D4FF"}
                    onBlur={e  => e.target.style.borderColor = "#1E2C4A"}
                  />
                </div>

                {/* Password */}
                <div style={{ marginBottom: 24 }}>
                  <label style={{ color: "#6B7DB3", fontSize: 12, fontWeight: 500, display: "block", marginBottom: 6, textTransform: "uppercase", letterSpacing: 0.5 }}>
                    Password
                  </label>
                  <div style={{ position: "relative" }}>
                    <input
                      type={showPass ? "text" : "password"} value={password}
                      onChange={e => setPassword(e.target.value)}
                      placeholder="••••••••••••" required
                      style={{
                        width: "100%", padding: "11px 44px 11px 14px", borderRadius: 8,
                        background: "#0A0E1A", border: "1px solid #1E2C4A",
                        color: "#E2E8FF", fontSize: 14, outline: "none",
                      }}
                      onFocus={e => e.target.style.borderColor = "#00D4FF"}
                      onBlur={e  => e.target.style.borderColor = "#1E2C4A"}
                    />
                    <button type="button" onClick={() => setShowPass(!showPass)} style={{
                      position: "absolute", right: 12, top: "50%", transform: "translateY(-50%)",
                      background: "none", border: "none", color: "#4A5578", cursor: "pointer", fontSize: 16,
                    }}>{showPass ? "🙈" : "👁️"}</button>
                  </div>
                </div>
              </>
            )}

            {step === "mfa" && (
              <div style={{ marginBottom: 24 }}>
                <label style={{ color: "#6B7DB3", fontSize: 12, fontWeight: 500, display: "block", marginBottom: 6, textTransform: "uppercase", letterSpacing: 0.5 }}>
                  Authenticator Code
                </label>
                <input
                  type="text" value={mfaToken} onChange={e => setMfaToken(e.target.value.replace(/\D/g,"").slice(0,6))}
                  placeholder="000000" maxLength={6} autoFocus
                  style={{
                    width: "100%", padding: "14px", borderRadius: 8, textAlign: "center",
                    background: "#0A0E1A", border: "1px solid #00D4FF44",
                    color: "#00D4FF", fontSize: 28, fontFamily: "monospace",
                    letterSpacing: 12, outline: "none",
                  }}
                />
                <button type="button" onClick={() => setStep("credentials")} style={{
                  marginTop: 10, background: "none", border: "none",
                  color: "#4A5578", fontSize: 12, cursor: "pointer", textDecoration: "underline",
                }}>← Back to login</button>
              </div>
            )}

            {/* Submit */}
            <button
              type="submit" disabled={loading || (step === "mfa" && mfaToken.length !== 6)}
              style={{
                width: "100%", padding: "13px", borderRadius: 10,
                background: loading ? "#1A2035" : "linear-gradient(135deg, #0050FF, #00D4FF)",
                border: "none", color: loading ? "#4A5578" : "#fff",
                fontSize: 14, fontWeight: 700, cursor: loading ? "not-allowed" : "pointer",
                transition: "all 0.2s", letterSpacing: 0.3,
                boxShadow: loading ? "none" : "0 4px 20px rgba(0,80,255,0.35)",
              }}
            >
              {loading ? "Authenticating..." : step === "mfa" ? "Verify Code" : "Sign In"}
            </button>
          </form>

          {/* OAuth2 SSO */}
          {step === "credentials" && providers.length > 0 && (
            <>
              <div style={{ display: "flex", alignItems: "center", gap: 10, margin: "20px 0" }}>
                <div style={{ flex: 1, height: 1, background: "#1E2C4A" }}/>
                <span style={{ color: "#4A5578", fontSize: 11 }}>OR CONTINUE WITH</span>
                <div style={{ flex: 1, height: 1, background: "#1E2C4A" }}/>
              </div>
              <div style={{ display: "flex", gap: 10 }}>
                {providers.map(p => (
                  <a key={p.id} href={`/auth/oauth2/${p.id}/login`} style={{ flex: 1, textDecoration: "none" }}>
                    <button style={{
                      width: "100%", padding: "10px 8px", borderRadius: 8,
                      background: "#0A0E1A", border: "1px solid #1E2C4A",
                      color: "#E2E8FF", fontSize: 12, cursor: "pointer",
                      display: "flex", alignItems: "center", justifyContent: "center", gap: 6,
                      transition: "border-color 0.15s",
                    }}
                    onMouseEnter={e => e.currentTarget.style.borderColor = PROVIDER_COLORS[p.id] || "#00D4FF"}
                    onMouseLeave={e => e.currentTarget.style.borderColor = "#1E2C4A"}
                    >{PROVIDER_ICONS[p.id] || p.name}</button>
                  </a>
                ))}
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        <div style={{ textAlign: "center", marginTop: 20, color: "#2A3555", fontSize: 11 }}>
          SentinelAI v1.0 · Built by Hassan Hamed Faris · FUE 2026
        </div>
      </div>

      <style jsx>{`
        input:focus { border-color: #00D4FF !important; box-shadow: 0 0 0 3px rgba(0,212,255,0.1); }
        @keyframes fadeIn { from { opacity:0; transform:translateY(-10px); } to { opacity:1; transform:translateY(0); } }
      `}</style>
    </div>
  );
}
