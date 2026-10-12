---
# ─────────────────────────────────────────────────────────────────────
# TEMPLATE POST — copy this whole folder, rename it, then edit.
#
#   cp -r content/posts/_template-post content/posts/my-new-slug
#
# The folder name becomes the URL slug: /posts/my-new-slug/
# Keep draft: true here so this template never publishes. Set it to
# false in YOUR copy when you're ready to go live.
# ─────────────────────────────────────────────────────────────────────

title: "My New Post Title"            # Shown as the heading + sidebar label
date: 2026-01-01                      # ⬅ CHANGE ME to the real publish date. Order = newest first; future dates are hidden.
draft: true                          # ⬅ set to FALSE in your real post to publish

# ── PLACEMENT — this is what decides the sidebar heading. ──
# Android → Mobile Hacking Labs/ :  categories ["Writeups"]  + tag "android"
# iOS     → Mobile Hacking Labs/ :  categories ["Writeups"]  + tag "ios"
# Android → DVRN/                :  categories ["DVRN"]
# DevSecOps/                     :  categories ["DevSecOps"]
# (A category not listed in layouts/posts/list.html = post still lives at
#  its URL and on the main list, but shows NO sidebar heading.)
categories: ["Writeups"]
tags: ["android", "frida"]           # tag "android"/"ios" also drives the MHL bucket

description: "One-line summary shown on the posts-list card and in meta tags."
showToc: true                        # table of contents in the left sidebar on the post page
---

Intro paragraph. Say what the target is and what you're going to do.

## First Heading

Write normally in Markdown. Inline `code`, **bold**, [links](https://example.com).

Drop screenshots in THIS folder (next to index.md) and reference them by
bare filename — no path:

![describe the screenshot](1.png)

```bash
# fenced code blocks get syntax highlighting + a copy button
frida -U -f com.target.app -l hook.js
```

## Second Heading

More content.

### Sub-heading

Nested sections show up in the ToC automatically.

## Wrap-up

Final thoughts / what you learned.
