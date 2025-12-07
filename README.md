<p align="center">
  <img src="https://cdn.discordapp.com/attachments/1100190571588489346/1442302994044686477/UTCCgXB.gif"
       alt="BetterMint RE Banner" />
</p>

<h1 align="center">🧠 BetterMint Reverse Engineering Challenge #1</h1>

<p align="center">
  Original crackme from the BetterMint community.<br/>
  The live race is over, but you can still try to break it for fun.
</p>

<p align="center">
  <a href="https://github.com/BetterMint/BetterMint-RE-1/releases/tag/Challenge">
    <img src="https://img.shields.io/github/downloads/BetterMint/BetterMint-RE-1/Challenge/total?style=flat&label=Challenge%20Downloads" alt="Challenge Downloads" />
  </a>
  <a href="https://github.com/BetterMint/BetterMint-RE-1">
    <img src="https://img.shields.io/github/stars/BetterMint/BetterMint-RE-1?style=flat&label=Stars" alt="Repo Stars" />
  </a>
  <a href="https://github.com/BetterMint/BetterMint-RE-1">
    <img src="https://img.shields.io/github/issues/BetterMint/BetterMint-RE-1?style=flat&label=Issues" alt="Issues" />
  </a>
  <a href="https://github.com/BetterMint/BetterMint-RE-1">
    <img src="https://img.shields.io/github/license/BetterMint/BetterMint-RE-1?style=flat&label=License" alt="License" />
  </a>
</p>

---

## 🎯 What This Repo Is

This repo contains:

- The **original challenge binary** used in the first BetterMint RE event  
- The **source code** for people who want to study how the protections were implemented (after solving, ideally)  

The live competition in the BetterMint Discord is over, but this crackme stays here as a **practice target** for anyone who wants to:

- Learn reverse engineering  
- Play with basic anti-analysis / obfuscation  
- Try patching a real-world-style challenge binary  

---

## 📥 Download the Challenge

Grab the original binary from the release:

➡️ **Release:**  
https://github.com/BetterMint/BetterMint-RE-1/releases/tag/Challenge  

**File provided:**

- `BetterMint_RE.exe` – the crackme binary

---

## 🧩 Goal of the Crackme

The core idea is simple:

> **Find the flag. Make the binary accept it.**

More specifically:

1. **Recover the flag** in the format:  
   `BETTERMINT{...}`
2. **Patch or manipulate the binary** so that it accepts your flag and reports success  
3. Bonus style points if you:
   - Keep the patch minimal
   - Bypass protections cleanly
   - Can explain what the protections were doing

This was originally rated:

> **Difficulty:** “not that hard tbh.”

So yeah, it’s meant to be accessible but not completely braindead.

---

## 🛡️ Protections & Tricks

The binary includes multiple layers of defense to make analysis a bit annoying, such as:

- Basic **anti-analysis / anti-debug style behavior**
- **Obfuscation** around important logic and strings
- Control-flow that **doesn’t immediately look obvious**
- A few things that are **“not what they seem”**

Nothing here is meant to be insane, but it’s closer to a **practical beginner–intermediate RE challenge** than a toy example.

If you’re new, treat this as a playground to:

- Load it up in your favorite tools (IDA, Ghidra, Binary Ninja, x64dbg, etc.)
- Step around, label functions, follow the flow
- Figure out **where** and **how** the flag is checked

---

## 🧪 Recommended Flow (If You’re Doing It For Fun)

1. **Download** `BetterMint_RE.exe` from the [Challenge release](https://github.com/BetterMint/BetterMint-RE-1/releases/tag/Challenge).  
2. **Run it in a VM / safe environment** (standard RE hygiene).  
3. **Poke it:**
   - Try random input
   - See how it behaves
   - Note any weird behavior, crashes, or messages  
4. **Load into a disassembler / debugger:**
   - Look for input handling and flag verification logic  
   - Rename functions, reconstruct what’s happening  
5. **Recover the flag** in the format `BETTERMINT{...}`.  
6. **Patch it** so the binary accepts your flag:
   - Modify conditional jumps
   - NOP out checks
   - Or do something more creative  
7. **Only then** peek at the source in this repo to:
   - Confirm your understanding
   - See how the protections were written
   - Learn how you might improve / break them further

---

## 🧠 For Learners

If you’re using this as a learning resource, try to answer:

- Where does user input go?  
- What does the flag check actually depend on?  
- What protections actually slowed you down vs. what was just noise?  
- How would *you* design a tougher version of this challenge?

Forks and writeups are welcome — just mark spoilers clearly if you publish them.

---

## 🌿 Future Challenges & Community

This was the **first** BetterMint RE challenge. Future ones (harder, probably more cursed) will be hosted in the Discord.

If you want:

- Early access to new crackmes  
- Reverse engineering races  
- Refactor-of-the-day style coding challenges  
- Game dev / scripting / security / tooling chaos  

join the community here:

👉 **BetterMint Discord**  
https://discord.gg/bettermint-development-1098267851732815932  

Watch for the `@Reverse Engineer This` ping for future events.

---

## ⚠️ Disclaimer

- Educational use only.  
- Don’t run unknown binaries outside of a controlled environment.  
- If you struggle… skill issue (but also, fr, it’s fine — ask questions, learn, come back stronger).

Enjoy breaking it. 🧩🧨
