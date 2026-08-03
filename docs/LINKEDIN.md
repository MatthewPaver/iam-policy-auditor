# LinkedIn kit — credibility + conversations + a usable link

Goal: look serious to cloudsec / hiring managers **and** let strangers try the product in one click.

Do **not** pitch “AI IAM auditor that replaces Access Analyzer.” Pitch: **who can delete prod — with receipts**.

---

## The link people actually open

**Stable (recommended for LinkedIn):** deploy to Fly, then use:

```
https://policylens-demo.fly.dev/?demo=1
```

One-time setup in your own terminal (needs interactive login):

```bash
cd ~/iam-policy-auditor
fly auth login
fly apps create policylens-demo --org personal   # or pick your org
fly deploy
```

**Temporary share link (machine must stay on):** a Cloudflare quick tunnel can expose local hosted mode. It dies when the process stops — fine for testing DMs, not for a LinkedIn post.

Repo: https://github.com/MatthewPaver/iam-policy-auditor

---

## Before you post (10 minutes)

1. Open `https://<host>/?demo=1` yourself — confirm Org fills in under 5s.
2. Attach **one** asset:
   - **A (best):** 20–40s screen recording of the hosted demo.
   - **B:** `docs/assets/demo-org.png`
3. Put the **live URL** in the **first comment**.
4. Post Tue–Thu, UK morning or early afternoon. Reply to every comment in the first 2 hours.

---

## Primary post (copy/paste)

```
Most IAM tools answer: “is this policy bad?”

The question I actually need in a change review is:
“Who can delete prod-1 — and how did they get that path?”

I built PolicyLens around that workflow.

• Load an AWS account authorization snapshot
• Ask who can run an action on a resource
• See multi-hop reach-admin paths (assume-role + escalation)
• Flag resource-policy exposures
• Every answer cites a source line

Design choice I’m sticking to: the engine produces the facts.
The LLM (optional) only explains them. It never decides what IAM permits.

Try the live demo (synthetic account — don’t paste secrets):
→ first comment

Honest limits: SCPs, permission boundaries, and session policies are labelled “not evaluated” — not silently ignored.

If you review IAM changes and want a design-partner loop (weekly snapshot + tell me which paths I’m missing), comment or DM.
```

Hashtags (optional, max 3): `#AWS` `#CloudSecurity` `#IAM`

---

## First comment (post immediately)

```
Live demo (auto-runs): https://<YOUR_DEMO_HOST>/?demo=1

What you’ll see in ~3 seconds:
• who can rds:DeleteDBInstance on prod-1
• multi-hop reach-admin paths with citations
• KMS/S3 resource-policy exposures

Then try another action in the Org tab, or upload your own (synthetic) snapshot.

Repo: https://github.com/<YOU>/iam-policy-auditor

Looking for 2–3 design partners who already do IAM change reviews.
```

---

## Credibility boosters (use 1–2, not all)

- Mention **IBM AI Security track** once, in the first comment — not the headline.
- Quote a concrete demo number: “demo snapshot: 9 principals, multi-hop reach-admin with citations.”
- Contrast without trash-talking: “complements Access Analyzer / Prowler — different question.”

---

## Conversation hooks (reply templates)

**“How is this different from Access Analyzer?”**
> Access Analyzer is strong on external/public resource access and policy validation. PolicyLens is aimed at the change-review question: who inside this snapshot can do X, and can they reach admin via multi-hop paths — with statement citations. Different job.

**“Does the LLM hallucinate permissions?”**
> By design it can’t invent grants. The deterministic engine answers; Claude only rephrases those facts with citations. The live demo runs with AI off — same who-can / reach-admin results.

**“Does it handle SCPs / permission boundaries?”**
> Not yet — and the UI says so. I’d rather under-claim than give a false sense of safety. That’s exactly the kind of gap I want design partners to pressure-test.

**“Open source? Pricing?”**
> Public demo + source on GitHub. Design partners get roadmap influence; I’m not selling seats yet.

**Someone shares a war story**
> That’s the use case. If you’re open to it, DM a redacted authorization-details export (or a synthetic one) and I’ll run it and send back the who-can / reach-admin cut.

---

## Who to engage (30 min after posting)

1. Comment thoughtfully on 5 recent posts about IAM privesc / least privilege / Access Analyzer.
2. Send **5 personal DMs**:

```
Saw you work on cloud IAM / platform security — I shipped a small tool that answers “who can do X” from an account snapshot with citations (engine-first, LLM optional).

Live demo: https://<YOUR_DEMO_HOST>/?demo=1

Not selling anything. Looking for 2–3 people who’d try a weekly snapshot and tell me which escalation paths I’m missing. Open to a look?
```

---

## Follow-up post (Day 5–7)

```
One thing that came up after I shared PolicyLens:

People don’t need another findings dump.
They need a path they can defend in a change review.

Live demo still here: https://<YOUR_DEMO_HOST>/?demo=1

If you tried it, what path did it miss in your mental model of AWS IAM?
```

---

## Success metrics (realistic)

| Signal in 7 days | Good | Great |
|---|---|---|
| Demo link clicks | 40+ | 150+ |
| Comments from practitioners | 5+ | 15+ |
| DMs | 2+ | 5+ |
| Design-partner intros | 1 | 2–3 |

Chase clicks + DMs harder than reaction count.
