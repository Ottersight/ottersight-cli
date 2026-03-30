---
platform: reddit
subreddit: r/SideProject
status: "DRAFT — DO NOT PUBLISH until Phase 11 (SEO + Waitlist) is complete"
adapted_for:
  - r/IndieHackers
  - r/solopreneur
---

# DRAFT — DO NOT PUBLISH

**Title:** I built an open-source dependency scanner that flags actively exploited vulnerabilities

---

**Body:**

Hey r/SideProject — sharing something I've been building.

**The problem:** Most developers don't know which of their dependencies have vulnerabilities. Dependabot helps but it's noisy — it surfaces every CVE, including theoretical ones that'll never be exploited in practice. What actually matters is: is this vulnerability actively being exploited right now? Is it in the CISA KEV catalog?

Existing tools either miss KEV enrichment entirely, require a paid account to see it, or bury it in noise.

**What I built:** OtterSight CLI — a local scanner that wraps Syft + Grype, enriches results with the CISA KEV catalog and EU Vulnerability Database (EUVD) mapping, and gives you a clean severity table. Free, MIT, no account needed.

```bash
npx @ottersight/cli scan .
```

[terminal screenshot showing scan output with CRITICAL/HIGH table and KEV flags]

Repo: https://github.com/Ottersight/ottersight-cli

---

The paid tier (OtterSight Cloud) adds scheduled scans, a multi-repo dashboard, and notifications when new CVEs hit your dependencies — https://ottersight.com

---

What would make you actually use this? I'm especially curious whether the KEV enrichment is useful or just noise for indie devs. Happy to discuss tradeoffs.
