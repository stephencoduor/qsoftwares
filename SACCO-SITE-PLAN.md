# Msacco → Sacco on qsoftwares.org — the plan

> The product the site calls **Msacco** is now **Sacco**: the Fineract-based core banking the branch
> already runs, plus **Sacco Field**, the tablet app field officers carry. This plan renames it
> everywhere on the site, gives it a product page built from the new tablet designs, and keeps every
> claim on the page to something the software actually does today.
>
> Branch `feat/sacco-product-page` · one PR · you merge (the site goes live from `main`).
>
> **Status (25 Sep 2026): built.** Every step in §7 is done on the branch; §8 records what was checked.

---

## 1. What changes, in one table

| Where | Today | After |
|---|---|---|
| Nav dropdown, 9 pages (`index`, `services`, `products`, `training`, `kobo-support`, `carbon-field`, `carbon-playbook`, `blog-sidebar-left`, `tools/playbook/template`) | `products.html#msacco` · "Msacco" | `sacco.html` · "Sacco" |
| `products.html` card 6 | "Msacco · Deployed" — back-office copy, dashboard screenshot | "Sacco · Deployed" — one sentence for the branch, one for the tablet; the tablet Home screenshot; **See Sacco →** goes to the page |
| `products.html` footer "Our Products" | Msacco | Sacco → `sacco.html` |
| `index.html` home teaser (4 cards) | AI Receptionist · CommitBot · GCIPay · NeoBank | **Decision D2** — recommended: Sacco replaces NeoBank as the most recent build |
| `img/products/msacco.png` | the branch dashboard | moved to `img/products/sacco/desktop.png`, still used (see §4) |
| `PORTFOLIO-UPDATE-README.md` | Msacco rows | Sacco rows |
| New | — | `sacco.html` (§3), `img/products/sacco/` (§4), `tools/site-check.mjs` (§6) |

Two dead links get fixed on the way: every nav pointed at `#msacco`, but the card's id was
`msacco-portfolio`, so the anchor never landed; and the card's *Request Demo* pointed at `#contact`,
which does not exist on `products.html`.

---

## 2. Naming (from `docs/redesign/BRAND-GUIDELINES.md` §1 in the app repo)

| Use | Word |
|---|---|
| The product / brand | **Sacco** |
| The tablet app | **Sacco Field** |
| The back office the branch runs | *Sacco at the branch* — never "Msacco", never "Sacco Core" (not a name the brand doc gives) |
| The institution type, in copy | "a SACCO", "SACCO staff" — the generic noun stays |
| Code identifiers | untouched (`com.msacco.*` — D8); not shown on the site |

The word "Msacco" survives on the site in exactly one place: the products card's HTML comment
recording the rename, so the next person knows where the old anchor went.

---

## 3. `sacco.html` — the page

Built on the `carbon-field.html` skeleton (same header, footer, section rhythm, `cf-` → `sf-` classes)
so it reads as the same site, with the page's own accent being the product's Emerald green
(`#1B4332` / `#2D6A4F` / `#D8F3DC`) rather than the site's teal — the one page on the site that wears
the product's colours, because the screenshots do.

| # | Section | What it says | Evidence on the page |
|---|---|---|---|
| 1 | **Hero** | Emblem + *Sacco*. Line: *One screen. One visit. No paper.* Sub: core banking for SACCOs on Apache Fineract, and the tablet your field officers carry. CTAs: *Request a demo* (mailto) · *Walk a day with it* (anchor) | The real Home screen in a CSS tablet frame |
| 2 | **Two surfaces, one ledger** | Left: *Sacco at the branch* (deployed) — loans, savings, accounting, M-Pesa & Airtel, reporting. Right: *Sacco Field* (in development, phases A–C built) — what the officer captures lands in the same ledger, and nothing on the tablet says *Posted* before the ledger confirms it | `desktop.png` beside `home.png` |
| 3 | **A day with Sacco Field** *(the centrepiece)* | A timeline of one officer's day, seven stops, each with a clock time, a kicker, a few sentences and the real screen: **07:40** the route, worst first · **08:30** Umoja's meeting, the keypad · **10:15** a stall, cash, *Payment Successful* · **11:00** an M-Pesa push — *PUSH SENT!*, not paid, and the guard against a second one · **12:30** a loan and the member's file, *Pay full amount* · **14:00** a passbook deposit · **16:45** back in signal, the Sync centre | `route`, `meeting-keypad`, `collect-cash` + `payment-successful`, `push-sent` + `already-on-phone`, `loan` + `member`, `deposit`, `sync-centre` |
| 4 | **Four words, never a fifth** | The honesty rule as a feature: *Waiting to sync · Posted · Failed · Discarded*. "Sent" is not "paid"; a push is a request the member has to accept. A 4-up of the result dialogs | `state-waiting`, `state-push-sent`, `state-successful`, `state-failed` |
| 5 | **Try the screens** *(interactive)* | A tablet frame with six buttons — Home · Route · Meeting · Collect · Member · Sync — that swap the screen. Vanilla JS, keyboard-reachable buttons, no library; without JS the first screen shows | the same files as §3 |
| 6 | **Also built in** | Nine small cards: Demo data mode (try it with no server) · Worst-first route with a glance card · Group meetings with attendance · Member file (accounts, charges, guarantors, collateral, next of kin, pinpoint) · Loan page with *Pay full amount* · Passbook deposits · Share a receipt · Sync centre with 30-day history · Two themes | icons only |
| 7 | **What the branch keeps** | The back-office feature list the old card carried, unchanged in substance: loan origination, appraisal and disbursement · savings and fixed deposits · accounting, tax and compliance · mobile-money collection with M-Pesa and Airtel through Payment Hub · custom reporting · multi-tenant | `desktop.png` |
| 8 | **Under the hood** | Four cards: the tablet app (Kotlin, Jetpack Compose, Room, WorkManager) · the outbox (saved first; one idempotency key sent three ways; read back before it says Posted) · Apache Fineract with the custom modules · Payment Hub. Tech tags | — |
| 9 | **Where the build stands** | *Built*: shell and design system · Home and Route · collecting money (cash, M-Pesa push, paybill, deposits) on the live Fineract poster · the demo day · 1,359 automated tests including screenshot parity at two tablet sizes. *Next*: member quick view and the loan and savings application panels · verification photos · registration · pilot. Honest, dated | — |
| 10 | **Designed in the open** | The "63 screens, designed in public" strip, captioned *frames from the design canvas, not the app* | `designed-in-public.png` |
| 11 | **Work with us** | Three asks: **Walk a day with us** (a SACCO field team to shadow — the Field Day card) · **Implementers** (Fineract / Mifos community — bring a tenant, we bring the tablet) · **Request a demo**. Email and WhatsApp already on the site | — |

Copy rules for the page (the same rules the app keeps):
- every screenshot is a capture of the real app on the tablet emulator running the labelled demo
  dataset — never a design-canvas frame presented as the app (§10 is labelled as canvas);
- no customer counts, no efficiency claims, no invented quotes;
- every number on the page is one we can point at (the test count is the CI gate on the merged
  branch; the screen count is the design canvas);
- the tablet app is *in development*, said plainly; the branch software is *deployed*.

---

## 4. Images — `img/products/sacco/`

All tablet captures are 1600×960 (the 2560×1600 device capture with the Android status bar cropped,
scaled to the site's width); the four result states are Roborazzi renders at 1600×1000; the brand
emblem is the owner's PNG at 320 px.

| File | Source (app repo) | Used in |
|---|---|---|
| `home.png` | `W01-home-device` (Home, demo day) | hero, products card, home teaser, §2, §5 |
| `route.png` | `C01-route-list-device` (today's walk) | §3 07:40, §5 |
| `meeting.png`, `meeting-keypad.png` | recaptured on the fixed build (a8b8311 + QA-C-122): Otieno part-paid, KES 1,430 still due, 1430 on the keypad | §3 08:30, §5 |
| `collect-cash.png`, `payment-successful.png` | `T05-filled-cash-device`, `T07-result-device` | §3 10:15 |
| `push-sent.png`, `already-on-phone.png` | `T07-push-sent-device`, `T05-from-loan-waiting-device` | §3 11:00 |
| `member.png`, `loan.png`, `deposit.png`, `picker.png` | `W12`, `W20`, `T17`, `C03c` | §3 12:30 and 14:00, §5 |
| `sync-centre.png` | `W03-sync-centre-device` | §3 13:20, §5 |
| `state-waiting/push-sent/successful/failed.png` | `T07-*-1280x800` renders | §4 |
| `desktop.png` | was `img/products/msacco.png`, with its app bar cropped off (it still read "Msacco") | §2 |
| `emblem-white.png` | `brand/logo/sacco-emblem-white.png` | hero |
| `og.png` (1200×630) | marketing `SL-01.png` | `og:image` |
| `designed-in-public.png` | marketing `MD-04.png` | §10 |

---

## 5. Decisions for you

Each was applied as recommended; any of them is a one-line change in the PR if you would rather not.

| # | Question | Recommendation (applied) |
|---|---|---|
| **D1** | URL and nav label | `sacco.html`, nav "Sacco" (the brand), page title "Sacco — core banking for SACCOs, and the Sacco Field tablet". The old `products.html#msacco` keeps working: the card gets both ids |
| **D2** | Home teaser | Replace **NeoBank** with **Sacco** — the teaser is "recent builds" and Sacco Field is the newest; NeoBank stays on the products page. Alternative: keep the four and add a full-width Sacco strip under them |
| **D3** | Status wording for Sacco Field | *In development* (as Carbon Field), never "Beta" — nobody outside the team has used it yet |
| **D4** | The Medium / Slack pieces | Not linked until they are published; the page says *ask for the design walkthrough* instead |

---

## 6. Checks before the PR

There is no test harness for the site, so the PR carries these, run and screenshotted:

1. `node tools/site-check.mjs` (new, ~60 lines): every `<img src>` and every local `href` on every
   page resolves; every `#anchor` link lands on an id; `msacco` appears nowhere but the one comment.
2. Local server (`python3 -m http.server 8080`) opened in the app's browser at desktop width and at
   375 px: hero, timeline, four-words grid, the interactive tablet (click each button; Tab to it), the
   products card, the home teaser, the nav dropdown on three pages. One screenshot each in the PR.
3. Lighthouse-style basics by hand: page weight under 4 MB (the images are ~4 MB total; lazy-loaded
   below the fold), `alt` on every screenshot describing what is on it, headings in order.
4. The playbook page is a *built* file (`tools/playbook/gate.mjs build` from private inputs we do not
   have here), so its nav is edited in both `tools/playbook/template.html` and `carbon-playbook.html`.

---

## 7. Order of work

| Step | Output | ~Time |
|---|---|---|
| 1 | Images exported (§4) — done with this plan | — |
| 2 | `sacco.html` with §3's eleven sections | 60 min |
| 3 | Rename on the 9 pages, the products card, the footer, the README | 15 min |
| 4 | Home teaser per D2 | 10 min |
| 5 | `tools/site-check.mjs` + run it | 15 min |
| 6 | Preview, screenshots, PR with the checklist | 20 min |
| 7 | You merge; the site is live | — |

Later, when the app reaches them: a *Download for Android* button (Play listing copy is already in
the brand guidelines §7), the pilot story, and the Medium links (D4).

---

## 8. What was checked (25 Sep 2026)

| Check | Result |
|---|---|
| `node tools/site-check.mjs` | 10 pages: every local link, image and anchor resolves; "Msacco" shown nowhere |
| Old links | `products.html#msacco` lands on the renamed card; the seven *Request Demo* buttons on `products.html` now reach `#contact` (they pointed at nothing before) |
| Desktop 1440 px | every section rendered and reviewed; the timeline's time pills clear the text; the hero tablet overlaps the next section as drawn |
| Phone 375 px | no horizontal overflow (`scrollWidth` = 375); the timeline collapses to one column; the screen picker's buttons wrap |
| Screen picker | clicking a button swaps the screen and the caption; arrow keys, Home and End move between buttons |
| Images | 23 files, 4.2 MB, all lazy-loaded below the fold; every one has alt text saying what is on it |
| Console | one pre-existing error on every page of the site (`scripts.js` calls `parsley`, which no page loads) — not touched here |
| Found along the way | recapturing the meeting exposed an app bug — a demo route refresh rewrote the day after a restart — fixed in `msacco-field` as QA-C-122 |

Not changed, and worth a look separately: `home-3-light.html` and `test.html` are theme leftovers that no page links
to; their own links point at demo pages that were never added. `tools/site-check.mjs` skips them by name.
