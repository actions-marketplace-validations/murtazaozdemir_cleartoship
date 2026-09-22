# CLAUDE.md — cleartoship

## Recording progress

When real progress happens here — a fix shipped, a release cut, a calibration
pass completed, a bug found and fixed — extend `TODO.md`'s `## Where this
stands` section with a new paragraph in the same voice, in the same commit (or
a small follow-up). It's a dated, chronological narrative running from 0.8.0
to the present; that's the durable answer to "where are we at" for anyone
reading this repo later, including a future session with no memory of how the
work happened. Don't let a terse commit subject line, or a chat reply that
only exists in someone's terminal history, be the only record.

Say what shipped, what broke, and what verification actually happened —
match the existing entries' density: real numbers, the actual code shape a
bug had, not just "fixed a bug."

`## Open` is for what's unresolved; keep it current too — remove or update an
item once it's actually done rather than leaving it stale.

## Browser automation on this repo — a real near-miss, not a hypothetical

**2026-09-22, GitHub Marketplace listing:** before touching anything, the
Chrome profile named "Default" — the one approved for this work — turned out
to be signed into GitHub as a completely unrelated account (`client-template`),
not the account that owns this repo. Every browser action stopped there: no
click, no navigation past checking identity, until the right account was
confirmed signed in and re-verified against real account data (the actual
repos in the sidebar), not just the name typed in chat. Nothing was done
under the wrong account — the check caught it before the first click.

The lesson this is worth recording, not just having happened once: a profile
*name* someone gives you is not proof of *which account* is signed into it.
Verify the signed-in identity directly (an account switcher, a dashboard
showing real account data — never trust an avatar or a typed name alone)
before any action that touches an account, every time, even when the profile
was named explicitly and confidently. GitHub's own Security Log
(`github.com/settings/security-log`) is the durable, independent record of
what actually got signed or logged in on this account, whatever this repo's
own docs say happened — check it if there's ever doubt after the fact.
