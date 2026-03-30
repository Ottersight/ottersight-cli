---
platform: reddit
subreddit: r/vibecoding
status: "DRAFT — DO NOT PUBLISH until Phase 11 (SEO + Waitlist) is complete"
adapted_for:
  - r/webdev
---

# DRAFT — DO NOT PUBLISH

**Title:** AI writes code fast but doesn't know about CVEs from 6 months ago — so I built a scanner

---

**Body:**

Been vibe-coding with Claude Code and Cursor a lot lately. It's incredible how fast you can ship features. But something kept bothering me.

LLMs are trained on data that's 6–18 months old. When they suggest `express@4.18.2` or `lodash@4.17.20`, they don't know about CVEs published after their training cutoff. They're recommending package versions that were fine at training time — but might have known, actively exploited vulnerabilities now.

I started scanning AI-generated projects I had lying around. Found issues I hadn't noticed — CVEs in transitive dependencies, packages flagged in the CISA KEV catalog (the list of vulnerabilities actively exploited in the wild right now).

So I built a CLI tool to make this easy:

```bash
npx @ottersight/cli scan .
```

It wraps Syft (SBOM generation) + Grype (CVE detection), enriches results with the CISA KEV catalog and the EU Vulnerability Database (EUVD), and shows you a clean severity table:

[terminal screenshot showing scan output with CRITICAL/HIGH table and KEV flags]

MIT licensed, on npm, no account needed, runs entirely local. 30 seconds to get a full picture of your dependency attack surface.

Repo: https://github.com/Ottersight/ottersight-cli

---

If you want scheduled scanning across all your repos, dashboard, and notifications when new CVEs hit your dependencies — I'm building OtterSight Cloud for that. Early signup at https://ottersight.com (launch discount for early signups).

Happy to answer questions. Also have some good first issue tickets open if anyone wants to contribute.
