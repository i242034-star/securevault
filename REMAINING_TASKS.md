# SecureVault — Status

Status as of 27 Nov 2026.

## Live

| | URL |
|---|---|
| App (Vercel) | https://securevault-nine-rho.vercel.app |
| API (Railway) | https://securevault-backend-production-8c4610c9.up.railway.app/api/health |
| Source (GitHub) | https://github.com/i242034-star/securevault |

Verified live: health OK; alice and charlie decrypt the sample PDF, bob and david get 403; Attack Lab 6/6
blocked; wrong password 401; CORS allows only the Vercel origin (and localhost for development).

## Done

- [x] BSW07 CP-ABE core (Charm-Crypto, BN254) + AES-256-GCM hybrid encryption
- [x] Key lifecycle: PBKDF2/AES-GCM envelopes, attribute changes, epoch revocation, re-encryption
- [x] HMAC-SHA256 tamper-evident audit chain
- [x] Attack Lab: 6 simulated attacks with countermeasures (backend + UI page)
- [x] Security fixes: admin-only enrolment, login lockout (HTTP 429), timing-safe login, upload size cap,
      forged-ciphertext crash → clean 403, no error-detail leakage
- [x] Docker image: non-root runtime, PBC tarball verified by SHA-256, Charm pinned to a tested commit
- [x] 75 automated tests passing (WSL Ubuntu, Python 3.12)
- [x] README, report (DOCX + PDF), presentation deck
- [x] GitHub repository (public), backend on Railway, frontend on Vercel

## Left for you

1. **Topic Selection Sheet:** add the GitHub link and the live app URL above.
2. **Rehearse** with `documentation_deliverables/SecureVault_Presentation.pptx` (speaker notes on every slide).
3. **Before the demo:** open the API health URL a minute early; a Railway trial service may need a moment to wake.
4. **Railway trial** lasts 30 days or $5 of usage. Don't pick a paid plan; it covers the evaluation period.
5. The live server starts from a fresh demo database after every redeploy, so files uploaded during a demo
   don't persist across deploys (by design: no persistent volume on the free tier).
