---
platform: reddit
subreddit: r/SaaS
status: "DRAFT — DO NOT PUBLISH until Phase 11 (SEO + Waitlist) is complete"
---

# DRAFT — DO NOT PUBLISH

**Title:** Open-sourcing my scanner core as a distribution strategy — anyone else doing open-core for dev tools?

---

**Body:**

I'm building OtterSight — a dependency security scanner for developers. Curious what this community thinks about the open-core model I'm using for distribution.

**The split:**

- **OSS (free):** CLI tool + scanner library, MIT licensed, on npm. Does SBOM generation, CVE detection, CISA KEV enrichment, EU Vulnerability Database mapping. Runs locally, no account.
- **Cloud (paid):** Hosted dashboard, automated scheduled scans across all repos, notifications when new CVEs hit your dependencies, EU compliance reporting (NIS2/CRA). This is the SaaS product.

I just published the OSS part: https://github.com/Ottersight/ottersight-cli

```bash
npx @ottersight/cli scan .
```

[terminal screenshot showing scan output with CRITICAL/HIGH table and KEV flags]

**The strategic thinking:** Dev tools live or die on trust and distribution. The free CLI builds both. Developers who use the CLI daily and want scheduled scanning + a dashboard across 20 repos become Cloud customers. The OSS scanner also functions as a sales demo — you can run it on your own code before handing over a credit card.

**The tension I'm navigating:** Maintaining a public OSS codebase takes time. I'm a solo founder. I'm trying to keep the OSS core stable and the Cloud features clearly separated so it doesn't feel like a bait-and-switch.

For those of you who've done open-core: how do you handle the OSS/paid balance? Where do you draw the feature line? https://ottersight.com if you want to follow along.
