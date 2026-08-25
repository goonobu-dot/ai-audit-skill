---
layout: guide
title: ai-audit in 3 Steps — Simple Guide
description: Have several different AIs audit your AI-written code and fix it until it passes — get closer to safe, quality code even if you can't read code
permalink: /simple-guide-en.html
---

# Your first look at ai-audit — what is this?

> You had an AI build your app. **It runs. But is it doing anything strange inside? Is it actually safe? You can't tell for yourself —**
> This tool answers that worry head-on.

You do **not** need to read code. This page skips the jargon and explains, in order, just two things: **what it's good for** and **how to use it**.

---

## Why this matters now

Today, even non-engineers can build real apps and business systems just by instructing an AI. Wonderful — but it comes with nagging doubts:

- 🔑 "Could it accidentally **leak** a customer's personal data, or a password or key?"
- 🤖 "Is it quietly doing **something I never asked for**?"
- 📦 "Is it using an old, **known-vulnerable component (library)**?"

An engineer would read the code and check. But **for a non-engineer, that isn't easy** — and trusting "an AI made it, so it's fine" is dangerous.

**ai-audit takes over that "checking" work for you — and crucially, it does not hand the job to a single AI.**

---

## The heart of it: reviewed by "eyes other than the maker's"

This is the most important idea.

Even for humans, **you miss the typos in your own writing, but a stranger spots them instantly.** AI is exactly the same: **the AI that wrote the code carries the assumption "I'm sure I got it right,"** so it overlooks its own mistakes.

So ai-audit has **a different company's AI — one that did not build the code** — audit it without those assumptions. We call this **cognitive independence.** It sounds fancy, but it just means: **let a third party who isn't the maker look at it with fresh eyes.**

### And more — several different-vendor AIs beat one

Here's the thing we most want you to see.

**The more different-vendor AIs you add — two, then three — the more they each find *different* holes,** because each AI has different strengths and different "habits" of looking.

This isn't theory. Here is **what actually happened when we had three AIs audit ai-audit itself.** The AI that built it (Claude) had left defects in — and the other companies' AIs found them, but **each AI found a *different* set of holes:**

| Which AI | Holes it found (real examples) |
|---|---|
| **Grok (xAI / via Cursor)** | · A deletion-permission check that could be **spoofed with a single marker file**<br>· A "highest severity" vuln (CVSS 9.8) **misread as "low"** and missed<br>· A wrong line-count on a sample screen |
| **Codex (OpenAI)** | · A **bypass** when the input path is a shortcut (symlink)<br>· **Broken/forged scan results** read as "all clear"<br>· A scan that said "whole history" but really **only looked at current files**<br>· An empty "seal" that could be created covering **zero files** |

👉 **Notice this: Grok and Codex found entirely *separate* holes.** With only one AI, half of this table would have stayed hidden. And in the very first round, **both AIs agreed on the same critical bugs** (like a data-loss risk) — so: everyone flags the big ones, and they divide up the subtle ones between them.

**Just by having several different-vendor AIs audit it, security and quality measurably improved this much.** That is the core value of this tool.

> ⚠️ **An honest disclaimer:** even so, this tool does **not** guarantee "safe." Its job is to **show, without hiding anything, what was checked and what is still unverified.** It never relabels "not tested" as "safe." That honesty is the point.

---

## How many AIs do I need? (Two is fine, three is recommended)

Plenty of people don't subscribe to Cursor (Grok). That's fine.

| Setup | Where it stands |
|---|---|
| **Claude + Codex (two)** | ✅ **Officially supported, minimum setup.** One set of non-maker eyes — cognitive independence holds |
| **Claude + Codex + Cursor (Grok) (three)** | ⭐ **Recommended.** You can rotate auditors each round and, as the table above shows, catch more *different* holes |
| Claude only (one) | Degraded mode. No independence, so it won't casually call anything "passed" |

So **start with two (Claude + Codex).** When you want a stricter look, add the third (Grok via Cursor) and more surfaces. If only one is available, the tool honestly writes that fact (auditors can't be rotated) into the report.

---

## Using it is just 3 steps

### Step 1 — Have your AI read this project

Just tell your AI (Claude Code / Codex, etc.):

```
Read https://github.com/goonobu-dot/ai-audit-skill
and add this skill to my project.
```

Your AI now recognizes `ai-audit` (the audit) and `code-atlas` (the internals view).

### Step 2 — Build your app as usual

Have the AI build your app the way you normally would. **You don't need to think about auditing while you build.**

### Step 3 — When you're done, say this one line

```
Audit the code and produce the report.
```

Then:

1. 🔒 **Machine checks** — for secret keys, personal data, and dangerous old components (honestly reporting NOT-TESTED when a dedicated tool isn't installed)
2. 🔍 **Independent audit by other companies' AIs** — Codex (and Grok, if available) hunt for defects using only the spec and code, *without* the building AI's explanations
3. 📋 **Evidence-backed report** — what was checked, what was found, what remains unverified

### To "finish it until it passes"

Don't stop at one pass — loop until no serious findings remain: "audit" → **fix** the findings → "audit again (ideally with a different AI)."

> 💡 Auditing uses external AI (your own Codex / Cursor subscription) — a slightly heavy step. When several rounds are likely, the AI first says "here's the scope, roughly this many rounds" before proceeding.

---

## FAQ

**Q. I can't read code — will the report make sense to me?**
A. The report is a mapping: *requirement → test performed → result → evidence.* And `code-atlas` visualizes the internals as diagrams and cards — just say "explain the internals in plain language." The visualization isn't all-seeing either: blind spots it can't follow are shown in red, never green.

**Q. Could my code or secrets leak to the external AI?**
A. Before anything goes out, a pre-send gate masks **known-format** secrets and personal data. But it's **not exhaustive** — unknown-format secrets and things like names/addresses can survive, so a human reviews the bundle before sending. And if *the code itself* is confidential, masking values doesn't by itself make it safe to send.

**Q. So, can I declare it "safe"?**
A. No — and that's the correct posture. What you get is not a declaration of safety, but **an honest map of what was checked and what hasn't been.** The final judgment stays with a human.

---

## Read next

- [Getting Started (5 minutes)](getting-started.html)
- [The Machine Gates at the Entrance — usage & philosophy](security-gates.html)
- [日本語:3ステップで使う ai-audit](simple-guide.html)
- Full manual (Japanese): [index](index.html)

---

*ai-audit is open source (MIT). GitHub: [goonobu-dot/ai-audit-skill](https://github.com/goonobu-dot/ai-audit-skill) — if it helps, a Star is appreciated.*
