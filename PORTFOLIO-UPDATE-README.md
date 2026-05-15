# Portfolio update — qsoftwares-site revamp (v2)

> 10 portfolio cards on products.html · 4-card teaser on home · full lifecycle taxonomy (Prototype → Backend wired → Beta → Pre-launch → Deployed → Live) · screenshots from real project repos.

---

## Local test

Server running at:

```
http://127.0.0.1:8089/
```

| URL | What to check |
|---|---|
| `http://127.0.0.1:8089/` | Home page · scroll to **"Recent Work · 10 PROJECTS · 5 VERTICALS"** teaser between "What We Do" and "Why QSOFTWARES" · team section now shows 3 members (Stephen, Andrew, Ambros) |
| `http://127.0.0.1:8089/products.html` | Products page · **portfolio section now at TOP** (dark teal gradient background, white headline, 10 cards in maturity order) · 3-card Platform Products section below |
| `http://127.0.0.1:8089/products.html#prodr-iq` | Anchor jump · ProdR-IQ card (Live · uses discovery-home screenshot) |
| `http://127.0.0.1:8089/products.html#msacco` | Anchor jump · Msacco card (Deployed) |
| `http://127.0.0.1:8089/products.html#pulseiq` | Anchor jump · PulseIQ card (Beta) |

### If the server isn't running

```bash
cd /d/qsoftwares-site
python3 -m http.server 8089 --bind 127.0.0.1
```

Server PID stored at `/tmp/qsw-server.pid` · kill with `kill $(cat /tmp/qsw-server.pid)`.

### Visual QA checklist

- [ ] Portfolio section has a deep-teal gradient background; eyebrow + headline + paragraph all white/legible
- [ ] Legend pill (Prototype / Backend wired / Beta / Pre-launch / Deployed / Live) renders as a translucent glass panel on dark
- [ ] All 10 product screenshots load (no broken-image icons)
- [ ] Status badges colored correctly: Live (teal-dark) · Deployed (teal-mid) · Beta (green) · Pre-launch (orange) · Backend wired (rust) · Prototype (light teal)
- [ ] Each card shows stack chips: Frontend ✓ · Backend ✓/○ · Live/Beta/todo
- [ ] Hovering each card lifts it slightly + scales the screenshot ~3%
- [ ] Tech-tag pills wrap cleanly on mobile (resize to 375px wide)
- [ ] Anchor links from home teaser jump to correct `products.html#<slug>`

---

## What was added / changed

### New CSS (in `css/custom.css`)

- `.q-portfolio-card` — screenshot-led card (distinct from icon-led `.q-prod-card`)
- `.portfolio-screenshot` — 16:9 framed image with hover zoom
- `.portfolio-status` + 6 variants (`.live` default, `.deployed`, `.beta`, `.preview`, `.backend-wired`, `.prototype`)
- `.portfolio-vertical` — eyebrow label
- `.portfolio-stats` — 4-up stats strip
- `.portfolio-section-header` — section title block
- `.portfolio-stack` + `.stack-item` (+ `.todo`, `.live`, `.beta` variants) — lifecycle chips inside each card
- `.portfolio-legend` + `.lgn-dot` color variants — visual lifecycle key
- `.portfolio-section-dark` — **dark gradient background** for the portfolio section, white header text

Palette: `#015055` teal-dark · `#0a7a7f` teal-mid · `#1cbf8a` green · `#f5a623` orange · `#c97b1f` rust · `#7ecdc8` teal-light.

### Images (in `img/products/` — 10 files)

| File | Source | Project · status |
|---|---|---|
| `ai-receptionist.png` | `D:\AI-Receptionist\screenshots\01-dashboard.png` | AI Receptionist · **Live** |
| `prodr-iq.png` | `D:\ProdR-IQ\screenshots\discovery-home-light.png` | ProdR-IQ · **Live** |
| `commitbot.png` | `D:\Commit-Bot\screenshots\02-heatmap.png` | CommitBot · **Pre-launch** |
| `gcipay.png` | `D:\gcipay-bank\screenshots\03-dashboard.png` | GCIPay Bank · **Deployed** |
| `neobank.png` | `D:\neobank\screenshots\04-dashboard.png` | NeoBank · **Deployed** |
| `msacco.png` | `D:\msacco\msacco-screenshots\03-dashboard.png` | Msacco · **Deployed** |
| `pulseiq.png` | `D:\PulseIQ\screenshots\03-pulse-home.png` | PulseIQ · **Beta** |
| `kalkuli.png` | `D:\kalkuli\screenshots\02-dashboard.png` | Kalkuli · **Beta** |
| `disbursepro.png` | `D:\disbursement-platform\screenshots\20-reports.png` | DisbursePro · **Prototype** |
| `fundflow.png` | `D:\fundflow-platform\screenshots\16-platform-analytics.png` | FundFlow · **Prototype** |

### HTML changes

| File | Changes |
|---|---|
| `products.html` | Portfolio section moved to **top** (above Platform Products); section now has dark teal gradient background; eyebrow updated to `RECENT PORTFOLIO · 10 PROJECTS · 5 VERTICALS`; 10 cards in maturity order (Live → Deployed → Beta → Pre-launch → Prototype); each card shows stack chips for Frontend/Backend/Live status; Platform Products reduced to 3 cards (Msacco moved into portfolio section) |
| `index.html` | Recent-Work teaser updated: `RECENT WORK · 10 PROJECTS · 5 VERTICALS`; CTA copy `View full portfolio · 10 projects`; team section reduced to 3 members (Bonface Nyakundi removed) |

### Portfolio order (top-to-bottom on products.html)

1. **AI Receptionist** (Live) — Multi-tenant voice-AI SaaS · 218 features
2. **ProdR-IQ** (Live) — Product/competitive intelligence platform
3. **CommitBot** (Pre-launch) — Closed-loop meeting agent for eng teams
4. **GCIPay Bank** (Deployed) — Private banking + BaaS on Fineract
5. **NeoBank** (Deployed) — Digital banking for Kenya & EAC
6. **Msacco** (Deployed) — SACCO management platform
7. **PulseIQ** (Beta) — Workforce pulse & insights
8. **Kalkuli** (Beta) — Construction estimation
9. **DisbursePro** (Prototype) — Disbursement orchestration
10. **FundFlow** (Prototype) — Treasury/fund-flow platform

---

## Push to live (GitHub Pages)

```bash
cd /d/qsoftwares-site
git status
git add img/products/ css/custom.css products.html index.html PORTFOLIO-UPDATE-README.md
git commit -m "feat: revamp products portfolio — 10 projects, lifecycle taxonomy, dark hero

- Portfolio section moved to TOP of products.html with dark teal gradient bg + white legible header
- Expanded status taxonomy: Prototype → Backend wired → Beta → Pre-launch → Deployed → Live
- 10 cards in maturity order, each with stack chips (Frontend/Backend/Live)
- 3 new projects added: Msacco, ProdR-IQ, PulseIQ
- DisbursePro + FundFlow screenshots replaced with complete dashboards
- ProdR-IQ screenshot swapped to discovery-home (richer than admin-overview)
- PRN Job Portal removed; Platform Products reduced from 4 → 3 (Msacco moved into portfolio)
- index.html: teaser counts + CTA updated; Bonface Nyakundi removed from team"

git push origin main
```

GitHub Pages rebuilds within 1-2 minutes. Verify at `https://qsoftwares.org`.

---

## Rollback (if needed)

```bash
cd /d/qsoftwares-site
git revert HEAD
git push origin main
```

---

## Open items / nice-to-have

1. Team grid drops from 4 to 3 — could bump `col-lg-3` → `col-lg-4` for tighter row fill (currently leaves space where the 4th card was)
2. Case-study pages per portfolio project (`case-studies/<slug>.html`) — content can be drafted from `D:\AI-Receptionist\docs\marketing\qsoftwares-portfolio.md`
3. `loading="lazy"` on portfolio screenshots — ~30% page-weight reduction on first paint
4. Footer "Recent work" sub-menu listing all 10 projects
5. Add the 3 new projects (Msacco, ProdR-IQ, PulseIQ) to `qsoftwares-portfolio.md` source-of-truth doc

---

## File diff summary

```
modified:   css/custom.css            (+ portfolio styles + status taxonomy + dark hero)
modified:   products.html              (portfolio moved to top · 10 cards · 3 platform cards)
modified:   index.html                 (teaser counts updated · team -1)
new file:   img/products/prodr-iq.png       (433 KB · discovery-home-light)
new file:   img/products/msacco.png         (70 KB · dashboard)
new file:   img/products/pulseiq.png        (346 KB · pulse-home)
modified:   img/products/disbursepro.png    (replaced — 20-reports.png)
modified:   img/products/fundflow.png       (replaced — 16-platform-analytics.png)
deleted:    img/products/prn-job-portal.png

Total: 10 portfolio screenshots in img/products/, ~2.3 MB.
```
