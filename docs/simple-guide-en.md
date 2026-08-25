---
layout: guide
title: ai-audit in 3 Steps — Simple Guide
description: Have a different AI audit your AI-built app, and fix it until it passes — the gentlest way in, no code-reading required
permalink: /simple-guide-en.html
---

# ai-audit in 3 Steps — Simple Guide

This is the gentlest possible introduction. **You do not need to read code to use it.** We skip the configuration details and answer just two questions: *what is it good for*, and *how do you start it*.

---

## First — what is this tool for?

More and more people have AI build their apps and systems. But you have probably felt this:

> "It runs... but is it doing anything weird inside? I can't actually tell if it's safe."

ai-audit answers that worry. Instead of asking the AI that **wrote** the code to check its own work, it has **a different company's AI (OpenAI's Codex, xAI's Grok) audit it with a stranger's eyes.**

### Why "a different AI"? — this is the whole point

In the human world, you miss the typos in your own writing, but someone else spots them instantly. AI is the same: **the AI that built the code carries the assumption "I'm sure I wired that up correctly,"** so it overlooks its own mistakes.

So we bring in **a separate-lineage AI that did not build it** and let it look without sharing those assumptions. We call this **cognitive independence.** While building this very tool, independent AIs repeatedly found defects the building AI missed — *with reproduction steps* — and some of them were bugs in this tool's own code.

### What you actually get (in plain words)

| Situation | With ai-audit |
|---|---|
| Before shipping an AI-built app | Machine gates stop secret keys and personal data from slipping in |
| Delivering to a company or client | You hand over not just "it works" but an **evidence-backed report**: what was checked, how far, and what is still unverified |
| You can't tell what's inside | There's a record a security expert can pick up — the basis for the judgment |
| You want higher quality | Independent AI audit surfaces problems; you fix, re-audit, and repeat **until no serious problems remain** |

> ⚠️ **An honest disclaimer:** This tool does **not** guarantee that software is "safe." Its job is to **show, without hiding anything, what was checked and what is still unverified.** It never relabels "not tested" as "safe." That honesty is exactly where its value lies.

---

## What's in this public repository

Clone it and you immediately get two skills plus the entry-gate scripts:

- **`ai-audit`** — runs the cross-vendor audit and produces a **technical audit report** linking requirements, tests, evidence, and unverified items.
- **`code-atlas`** — visualizes the internals as diagrams and key-point cards so a non-engineer can "grasp it instead of reading it."
- **`security_gate`** (scripts) — machine gates that stop secrets, personal data, and vulnerable dependencies *before* they get in.

> ℹ️ The convenience trigger that "runs the whole loop from one sentence" (`quality-audit-loop`) is a **separate add-on skill** in the author's own setup and is **not yet bundled** in this public repo (its trigger design is being revised to prevent accidental launches). The 3 steps below rely only on the bundled `ai-audit`.

---

## Using it is just 3 steps

### Step 1 — Have your AI read this project

Point your AI (Claude Code / Codex, etc.) at this repository. The easiest way is simply to say:

```
Read https://github.com/goonobu-dot/ai-audit-skill
and add this skill to my project.
```

Your AI now recognizes `ai-audit` and `code-atlas`.

### Step 2 — Build your app as usual

Have the AI build your app or system the way you normally would. **You don't need to think about auditing while you build.**

### Step 3 — When you're done, say this one line

Once the code is finished, just tell the AI:

```
Audit the code and produce the report.
```

`ai-audit` starts, and:

1. 🔒 **Machine gates** — check for secret keys, personal data, and known-vulnerable dependencies (and honestly report NOT-TESTED when a dedicated tool isn't installed)
2. 🔍 **Independent AI audit** — Codex and Grok hunt for defects using only the spec and the code, *without* the building AI's explanations
3. 📋 **Evidence-backed report** — what was checked, what was found, what remains unverified — plus a tamper-evident seal

### To "finish it until it passes" (running the loop)

Don't stop at one audit — loop until nothing serious remains:

1. "Audit the code" → receive the report
2. **Fix** the findings (fixing and auditing are approved separately)
3. "Audit again" → re-audit from a fresh angle / a different AI
4. Repeat 2–3 until no serious findings remain

> 💡 Auditing uses external AI (your own Codex / Cursor subscription) — a slightly heavy step. When several rounds are likely, the recommended practice is for the AI to first say "here's the scope, roughly this many rounds" before proceeding.

---

## FAQ

**Q. I can't read code — will the report make sense to me?**
A. The report is a mapping table: *requirement → test performed → result → evidence.* And `code-atlas` visualizes the internals as diagrams and cards. Just say "explain the internals in plain language." Note the visualization is **not** all-seeing either: blind spots (parts it could not analyze) are shown in red, never green.

**Q. Could my code or my secrets leak to the external AI?**
A. Before anything goes to an external AI, it passes through a pre-send gate that masks **known-format** secrets and personal data. But this is **not exhaustive** — unknown-format secrets and things like names/addresses can survive, so a human reviews the bundle (transmission-ledger.json) before sending. And if *the code itself* is confidential, masking values does not by itself make it safe to send. Tools that send code to the cloud were deliberately not adopted, so the leak-prevention tool never becomes the leak.

**Q. Can I then declare it "safe"?**
A. No — and that's the correct posture. What this tool gives you is not a declaration of safety, but **an honest map of what was checked and what has not yet been checked.** The final judgment stays with a human.

---

## Read next

- [Getting Started (5 minutes)](getting-started.html) — for when you want to get hands-on
- [The Machine Gates at the Entrance — usage & philosophy](security-gates.html) — stopping leaks *before* they get in
- [日本語:3ステップで使う ai-audit](simple-guide.html)
- Full manual (Japanese): [index](index.html)

---

*ai-audit is open source (MIT). GitHub: [goonobu-dot/ai-audit-skill](https://github.com/goonobu-dot/ai-audit-skill) — if it helps, a Star is appreciated.*
