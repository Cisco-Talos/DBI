# Contributing to Talos DBI tools

Thanks for your interest in contributing! We’re excited to collaborate with you. This project thrives when people share tools, ideas, and **their own DBI clients** with the community.

**Short version**

- Be kind and constructive
- Open an issue or discussion before changes.
- For fixes/feats: fork → branch → PR with a clear description.
- **Your own DBI clients are very welcome, no matter if they are perfect or not!** 
- By submitting a contribution, you agree it will be licensed under the project’s [Apache-2.0](LICENSE).
- Add your own clients to the **contributors directory called '3rdparty'**
- Bug fixes for serious bugs or optimizations are welcome, but keep in mind these are RE clients, they do not need to be 100% perfect
- People using them, should be skilled enough to know when and where to use them (or not)
- Never run the clients on a production machine, always use a VM or dedicated malware PC
- Keep in mind DBI is really executing the target application (e.g. malware sample) it is NOT emulation!

---

## How can I contribute?

There are many ways to help:

- **Add DBI clients** (new tools, integrations, helpers) and share them with everyone.
- Report serious bugs, edge cases or optimization opportunities.
- The clients are kept simple on purpose to make it easier to understand them
- They are not bullet proof and don't need to, they are for educational use only
- Improve documentation and examples.
- Review pull requests and help triage issues.

If you’re unsure whether something fits, open a small issue to ask—we’re friendly!

---

## Contributing DBI clients

We’re **especially happy** to accept your DBI clients so others can use and learn from them. To make review quick and painless:

### Location & layout

- Put your clients under `3rdparty/` (create subfolders if needed), `3rdparty/<client-name>/...`  
- Include a short `README.md` alongside complex clients explaining **what it does**, **inputs/outputs**, **requirements**, and **examples**.

### Script header metadata

Each client should include a short, commented header with metadata:

--- Sample Metadata ---
name: short, human-friendly name
description: what the client does
language: C|python|other
platforms: linux, macos, windows (list all that apply)
dependencies: e.g., python>=3.11; requests; jq
inputs: env vars / flags / files required
outputs: files emitted or stdout format
author: your name or handle
license: Apache-2.0 (preferred) unless noted otherwise
tags: dbi, networking, forensics,... 

