# 🛡️ DotNet-Armor-Ecom
Enterprise-grade OWASP Grade A+ security shield &amp; in-memory WAF for ASP.NET Core e-commerce with safe passage for Meta Pixel, GTM, and Microsoft Clarity.


> **Production-Ready OWASP Grade A+ Security Shield & In-Memory WAF for ASP.NET Core E-Commerce**

[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![Security Rating](https://img.shields.io/badge/SecurityHeaders-Grade%20A-success?logo=security)](https://securityheaders.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An enterprise-grade, high-performance middleware architecture designed to protect ASP.NET Core web applications and e-commerce platforms against automated scanning tools, brute-force attacks, and modern web exploits—without breaking marketing tracking pixels, payment gateways, or modern UI frameworks.

---

## ⚡ The Challenge It Solves

Most standard security configurations break production e-commerce sites:
1. **Aggressive CSP Breaks Tracking:** Strict Content Security Policies often block **Meta (Facebook) Pixel**, **Google Tag Manager (GTM)**, **GA4**, and **Microsoft Clarity**.
2. **Mobile CGNAT Rate-Limit Failure:** Strict per-IP rate limits block legitimate mobile data users (e.g., shared CGNAT IPs across telecommunication providers) during active ad campaigns.
3. **Proxy IP Collapses:** When hosted behind CDNs (Cloudflare) or shared load balancers, naive IP detection limits the CDN edge instead of the visitor.

**DotNet-Armor-Ecom** provides a balanced, hardened layer that protects the backend while keeping business operations, tracking analytics, and checkout flows intact.

---

## 🚀 Key Features

- **$O(1)$ In-Memory WAF:** Intercepts automated vulnerability scanners (Nikto, Sqlmap, Nmap, Nuclei, DirBuster, FFUF) and directory-traversal attempts before hitting controllers.
- **Smart Hybrid Content Security Policy (CSP):** Full whitelisting for Tailwind CDN, Google Fonts, Meta Pixel, GTM, GA4, TikTok Pixel, and Microsoft Clarity.
- **CGNAT-Friendly Sliding Window Rate Limiter:** Handles sudden burst traffic and shared carrier IPs without serving false `429 Too Many Requests` to genuine buyers.
- **Multi-Layer IP Forwarding:** Automatically identifies real client IPs behind Cloudflare (`CF-Connecting-IP`) and reverse proxies (`X-Forwarded-For`).
- **Session Hardening & Cache Probing Defense:** Cookie isolation with `SameSite=Lax`, `HttpOnly`, and strict `no-store` headers for sensitive admin and checkout endpoints.
- **Server Fingerprint Cloaking:** Strips `Server`, `X-Powered-By`, and `X-AspNet-Version` response headers.

---

## 📦 Quick Installation

1. Copy the optimized middleware pipeline into your `Program.cs` file.
2. Ensure your required database contexts and MVC services are registered.
3. Run the project:
   ```bash
   dotnet build
   dotnet run
