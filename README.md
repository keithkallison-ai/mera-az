# Mera
Arizona hospital price-transparency explorer. Static site, two views:
- **index.html** — the CFT explorer (HonorHealth + Banner, 26 hospitals): how each hospital's file was generated — its recovered internal base, payer dials, composition. Multiples shown are vs each hospital's own recovered base.
- **multiplier_app.html** — the payer multiplier (27 hospitals incl. critical-access): every commercial plan's negotiated rate as a multiple of the public CMS schedule (OPPS standalone-payable / CLFS), with per-hospital coverage disclosure. Same data, different ruler — the two views are not comparable 1:1 (each page explains).

Data: byte-exact Arizona hospital MRF captures (CY2026 files) × CMS 2025 schedules.
