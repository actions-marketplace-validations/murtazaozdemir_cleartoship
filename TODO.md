# ClearToShip — roadmap

Public backlog. Working notes, positioning and anything about other projects
live in `NOTES.private.md`, which is gitignored and stays on my machine.

_Current release: **v0.13.8**. Since v0.13.6 the RLS / Server Actions /
LLM-agent suites live in the private `cleartoship-rules-pro` repository, and
v0.13.6's own release run is red — it ran the old workflow, which still tried npm,
and a re-run uses the workflow as it was at the tag. The release itself is fine. Install from
[cleartoship.app](https://cleartoship.app/cleartoship.mjs)
(`curl -fsSL https://cleartoship.app/cleartoship.mjs -o cleartoship.mjs && node cleartoship.mjs`);
the same file is on [the GitHub release](https://github.com/murtazaozdemir/cleartoship/releases/latest).
**Not distributed through npm, by decision (2026-09-21):** the maintainer can no
longer use npmjs.com. The package was unpublished on 2026-09-03 and the name is
unclaimed, so anything on the registry under it is **not from this project**:
the docs say so, and the Action and CI no longer run or recommend it.
`release.yml` has no npm publish steps any more (removed 2026-09-21); the
`NPM_TOKEN` secret it used is dead and can be deleted from the repository.
`release.yml` verifies that the release carries a bundle that runs and reports
its version, and `deploy-site.yml` serves that build from the domain and compares
its hash with the release asset after every deploy._
_v0.13.0 and earlier published **unsigned** — npm's registry refuses provenance
from a private source repo. The repository is public now, and `release.yml`
reads its visibility, so 0.13.1 is the first release signed with provenance._

## Where this stands

Fourteen releases, 0.8.0 → 0.13.5. The calibration work is the point of the project
so far: across a five-repo corpus the tool went from 2,290 findings to a few
hundred, and from 157 criticals to a handful — **every removal verified by
reading the code it was about**, never by adjusting a threshold. Reports that
name a real problem are worth more than reports that cover a table.

0.13.0 added the three agent rules (CTS083/084/085) and made the LLM/agent
surface the headline rather than the fifth section. 0.13.1 was the first signed
release. 0.13.2 raised the Node floor onto Babel 8.

**0.13.3 is the first release fixed by code I did not write.** Scanning
vercel/ai-chatbot, modelcontextprotocol/servers and assistant-ui turned up two
real defects in one afternoon that six repositories of my own never showed: paths
were reported relative to the shell's cwd rather than the scanned repo, and
CTS083 matched `clients.delete(id)` on an in-memory `Set` because the root
pattern accepted a prefix instead of a whole segment. Both were exactly the kind
of thing dogfooding structurally cannot find — my repos all sit beside this one,
and I would never have written `clients` for a Set.

**0.13.5 is a full self-audit, and the self-scan is why most of it was found.**
Ten defects, every one reproduced before it was fixed and covered by a test
after. Three of them fired on other people's correct code — a repository with a
`site/` directory had that whole subtree reported clean without a file being
opened; a library whose README says `npm install <its own name>` before the
first publish got a *critical* hallucinated-dependency finding; and `/.env` or
`.env.local` in a `.gitignore` were both reported as failing to cover the file
sitting next to them, because CTS032 compared the text against five literal
strings instead of asking the matcher this repo already ships. A fourth was
quieter and worse: OSV publishes `severity[].score` as a CVSS *vector*, so
`Number()` returned `NaN` on every GitHub-sourced advisory and a 9.8 and a 5.3
were both reported `high` — the "by CVSS" column was not what happened.

The pattern worth keeping: the CI self-scan read `src` and nothing else, so the
README, the manifests, the shipped Action and the landing page were never
scanned by the tool that scans them for everyone else. Pointing it at all of
them found a credential-shaped literal in a comment written the same afternoon.

## Open

- [ ] **Wire up Stripe billing.** `site/src/stripe-webhook.ts` and
      `stripe-client.ts` are already written — webhook-driven license
      grant/revoke on `customer.subscription.*` events — but not live:
      `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET` are unset, and there's no
      Checkout flow or webhook endpoint configured in the Stripe dashboard yet.
      Deferred on purpose: first licenses are being issued **manually** against
      PayPal payments (see `/admin/license/issue`) so the rest of the pipeline —
      D1 schema, Ed25519 token signing, `/license/verify` — gets proven out
      end to end before adding a payment processor into the loop. Also still
      open whenever this resumes: `currentPeriodEnd()`'s field-name fallback in
      `stripe-webhook.ts` needs re-checking against whichever Stripe API
      version the real account ends up pinned to.
- [ ] **List the Action on the Marketplace.** `uses: murtazaozdemir/cleartoship@vX`
      resolves for anyone now, and `action.yml` already carries the branding a
      listing requires. What is left cannot be scripted: there is no
      `marketplace` field on the release object and `/marketplace_listing` is not
      writable, because publishing means **accepting the GitHub Marketplace
      Developer Agreement**. That is a legal acceptance, so it has to be done by
      hand on the release page. The `curl … cleartoship.mjs` recipe in the README works
      everywhere regardless, and on any CI, not just GitHub.
- [ ] **Get it in front of people, as early as possible.** Publish and publicize
      now; there is no minimum number of users to reach first (decided 2026-09-21).
      Every calibration decision so far was made against my own six repositories,
      which remains the biggest weakness in the tool's judgement, but the way to
      fix it is more people running it and reporting what comes back wrong, not
      recruiting a set number of testers before launching.

## Later — recorded, not being worked on

- **Trademark "ClearToShip".** The code is MIT and the package is public, so the
  licence deliberately lets anyone copy, modify and sell it — that is the trade,
  and it is the same one gitleaks and GuardVibe made with this project. What MIT
  does *not* grant is the name, and a trademark is the only protection here that
  actually works: a fork may take every line and still cannot call itself
  ClearToShip, which leaves the discoverability with the original.
  **Parked deliberately, not forgotten.** At zero users there is nothing to pass
  off and nobody to confuse, which is what a trademark protects against. The
  moment to file is when the name starts carrying weight — real users, a
  Marketplace listing, or the first time somebody else ships something built on
  this. Revisit then rather than on a date.

## Settled

- **No npm distribution, as of 2026-09-21.** ClearToShip ships as a GitHub Release
  plus `cleartoship.app/cleartoship.mjs`. The Action resolves the release bundle,
  then a checkout build, and never `npx`es the name — with the name unclaimed, that
  would be code execution for whoever registered it. The scanner still *queries*
  the npm registry, because checking a user's dependencies against it is the
  feature; when it cannot, the run says so and is never "clear".

- **Node floor: `^22.18.0 || >=24.11.0`,** as of 0.13.2. That is Babel 8's own
  range copied exactly rather than approximated — a looser `>=22.18` would claim
  Node 23 and 24.0–24.10 work, and Babel 8 does not support them. Node 18 and 20
  are dropped. CI tests the declared floor (`22.18.0`) alongside the latest 22
  and 24, so a claim the code cannot meet fails the build rather than a user's.
  Worth being clear why the exactness matters here rather than being pedantry:
  had the range been wrong, the tool would have installed happily and then failed
  at *parse* time — and an unparsed file produces **no findings**, not an error.
  A scanner's worst failure is reporting clean on code it never read.
  ⚠️ **Local dev needs a newer Node than this machine's default.** `node` on the
  PATH here is v22.14, below the floor. Homebrew's v26 satisfies it:
  `export PATH="/usr/local/opt/node/bin:$PATH"` before `npm install` or `npm test`.

## Deliberately not covered, and why

These are decisions, not gaps waiting to be filled. Adding a rule for any of
them would be box-checking, which is the failure mode this project exists to
avoid.

- **OWASP A06 (Insecure Design).** Missing threat modelling is an architecture
  concern that no static read detects. Revisit only if a genuinely high-signal
  design-flaw pattern turns up.
- **OWASP LLM05 (Data & Model Poisoning).** Needs training-pipeline and dataset
  provenance. Nothing in a web app's source tree answers it.
- **Strengthening A04 / A02 first-party.** Parked on purpose rather than by
  neglect: five repos were triaged and no real gap showed up. Speculative rules
  are how a scanner becomes noise.

## Deliberately not built

- **A cross-finding risk graph** correlating web findings with LLM findings.
  It is an existing category, and a *Critical* assembled out of two mediums is
  exactly the false-positive behaviour that eight releases went into removing.
- **An auto-fix PR bot.** `--fix-prompt` and SARIF already cover the useful part
  at none of the cost.
- **Broader generic SAST/SCA.** Saturated, free at the entry point, and not a
  reason anyone would choose this tool.

## Pricing

**Everything is free while ClearToShip is in beta (decided 2026-09-21).** The
RLS, Server Actions and LLM/agent suites had been split into a private
`cleartoship-rules-pro` repository for a planned $5/month Pro tier. They are back
in this repository, MIT licensed, and ship in the free bundle. Why: a separate
package cannot be installed now that npm is out, so an unpublished paid tier
delivered nothing; the tool's headline features (the agent surface) were missing
from the download; and the same rules had been public under MIT since v0.4.

The private repository and the license-issuing Worker under `site/` (D1 database,
Ed25519 token signing, Stripe webhook code) remain, dormant, in case a paid tier
is ever wanted. Nothing charges anyone. No price is set — $5/month was only ever a
plan — and what is free now stays free.

## Contributing

The most useful bug report here is a **false positive, with the code that caused
it**. A rule that fires on correct code is a worse bug than a rule that misses
something: one wastes your afternoon and teaches you to ignore the tool, the
other you never knew about. Removing false positives is what most of this
project's history is actually made of, and every removal so far was verified by
reading the code it was about rather than by loosening a threshold.

Second most useful: a **missed finding**, with the code it should have caught.

New rules are welcome, but the bar is deliberately high — a rule that cannot
name a specific wrong thing a developer would act on does not go in, however
well it maps to a compliance table.
