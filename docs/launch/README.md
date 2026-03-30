# Launch Post Drafts

**STATUS: DO NOT PUBLISH until Phase 11 (SEO + Waitlist) is complete.**

Before driving traffic via Reddit or any social channel, ottersight.com must have:

- A working waitlist form (email capture)
- `robots.txt` with correct directives
- `sitemap.xml` submitted to Google Search Console
- Structured data (Organization + SoftwareApplication schema)

Publishing posts without these in place wastes the traffic spike. Phase 11 completes this infrastructure. Do not publish until all items above are verified live.

---

## Soft Launch Plan

Post in this order. Wait 24–48 hours between each subreddit to gauge response and adapt.

| Order | Subreddit | Target audience | Post file |
|-------|-----------|-----------------|-----------|
| 1 | r/vibecoding | Vibe coders using AI tools (Claude Code, Cursor) | reddit-vibecoding.md |
| 2 | r/SideProject | Indie devs and side project builders | reddit-sideproject.md |
| 3 | r/SaaS | SaaS founders (open-core strategy angle) | reddit-saas.md |
| 3 | r/IndieHackers | Indie hackers — adapt from reddit-sideproject.md | — |
| 3 | r/solopreneur | Solo founders — adapt from reddit-sideproject.md | — |
| 4 | r/webdev | Web developers — adapt from reddit-vibecoding.md | — |

---

## Broader Launch (Deferred)

These channels are deferred until after soft launch validation and v1.0 hosted service launch:

- r/devops
- r/opensource
- r/cybersecurity
- Hacker News (Show HN)
- Dev.to article
- Twitter/X thread

---

## Launch Angle

**Core message:** AI-generated code uses outdated dependencies because LLM training data is stale (6–18 months old). Vibe coders and indie devs ship code with known CVEs baked in. OtterSight CLI catches these in seconds — free, local, no account needed.

**Secondary angle (SaaS/founder communities):** Open-core as a distribution strategy. CLI is free and MIT-licensed. Cloud is the hosted tier for teams who want dashboards and scheduled scans.

---

## Posting Guidelines

- **Tone:** Technical builder, first person, personal account — not brand account
- **Format:** Problem statement → terminal screenshot → repo link → brief hosted service mention
- **Personal account:** Post from your personal Reddit account, not a brand account. Communities distrust brand accounts.
- **No excessive self-promotion:** Follow subreddit rules. Lead with value. The CLI is free — lean into that.
- **Adapt to subreddit culture:** r/vibecoding expects AI/vibe context. r/SaaS expects business framing. Do not cross-post verbatim.

---

## Post Checklist

Before publishing any post, verify:

- [ ] Waitlist form on ottersight.com is working (email captured in DB)
- [ ] `robots.txt` is live at ottersight.com/robots.txt
- [ ] `sitemap.xml` is live and submitted to Google Search Console
- [ ] Terminal screenshot captured showing CRITICAL/HIGH table with KEV flags
- [ ] Each post adapted to the target subreddit's rules and tone
- [ ] Posting from personal Reddit account (not brand account)
- [ ] Links tested: repo link, `npx` command, ottersight.com waitlist
