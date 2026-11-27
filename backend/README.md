---
title: SecureVault Backend
emoji: 🔐
colorFrom: indigo
colorTo: blue
sdk: docker
app_port: 10000
pinned: false
short_description: CP-ABE (BSW07) document locker API - CS-3002 term project
---

# SecureVault backend (Flask + Charm-Crypto CP-ABE)

This folder is the REST API of SecureVault. The block above configures it as a
Hugging Face Docker Space; GitHub ignores it.

- Health check: `GET /api/health` returns `{"status":"ok"}`
- Full documentation: see the repository root `README.md`

Required Space secrets: `FLASK_ENV=production`, `JWT_SECRET`, `AUDIT_HMAC_SECRET`,
`MASTER_KEY_PASSPHRASE`, `CORS_ALLOWED_ORIGINS`, `SEED_DEMO_DATA=true`.
