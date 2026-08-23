# Praxis — Browser Action Firewall for OpenClaw

> Control what your OpenClaw can do in the browser. Prove what it did.

## What This Skill Does

Praxis adds **action-level governance** to OpenClaw's browser control. Before your OpenClaw clicks a button, navigates to a URL, or fills a form, Praxis checks the action against your security policies.

### Three Layers of Protection

1. **UI Action Firewall** — Block dangerous browser actions based on YAML policies (e.g., "never click Pay Now", "block all /admin/ URLs")
2. **Evidence Vault** — Every action is recorded in a tamper-evident, hash-chained audit trail you can replay and verify
3. **Capability Tokens** — Give your OpenClaw time-limited, scoped permissions (e.g., "browse bank.com for 30 minutes, read-only")

## Setup

Praxis runs as a **sidecar service** alongside your OpenClaw:

```bash
# Install Praxis
pip install praxis-agent

# Start the sidecar (runs on port 18790)
praxis sidecar --port 18790 --policy finance-safe

# Or with custom policies
praxis sidecar --port 18790 --policy-dir ~/.openclaw/workspace/skills/praxis/policies
```

The sidecar must be running for this skill to work. You can start it in a separate terminal or as a background service.

## How It Works

When this skill is active, you should call the Praxis sidecar API **before** executing browser actions. The flow:

1. You want to navigate/click/type in the browser
2. First, call `POST http://localhost:18790/api/v1/evaluate` with the action details
3. If `allowed: true` → proceed with the browser action
4. If `allowed: false` → report the block to the user and do NOT execute the action

## API Reference

### Check if an action is allowed

```bash
curl -X POST http://localhost:18790/api/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "action_type": "click",
    "url": "https://bank.com/invoices",
    "element_text": "Pay Now",
    "agent_id": "openclaw"
  }'
```

Response:
```json
{
  "allowed": false,
  "decision": "block",
  "risk_level": "high",
  "reason": "Element text matches high-risk keyword: 'pay'",
  "record_id": "a1b2c3d4e5f6"
}
```

### Start an evidence session

```bash
curl -X POST http://localhost:18790/api/v1/sessions \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "openclaw", "purpose": "Check invoices"}'
```

### Issue a capability token

```bash
curl -X POST http://localhost:18790/api/v1/tokens \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "openclaw",
    "purpose": "Read-only bank access",
    "ttl_minutes": 30,
    "domains": ["bank.com"],
    "exclude_text": ["Pay", "Transfer", "Delete"]
  }'
```

### Check sidecar health

```bash
curl http://localhost:18790/api/v1/health
```

## Browser Action Integration

When using OpenClaw's browser tool, apply this pattern:

### Before navigating
```
Before navigating to any URL, call the Praxis sidecar:
POST http://localhost:18790/api/v1/evaluate
Body: {"action_type": "navigate", "url": "<target_url>", "agent_id": "openclaw"}

If allowed is false, tell the user: "🚫 Praxis blocked navigation to <url>: <reason>"
```

### Before clicking
```
Before clicking any element, call the Praxis sidecar:
POST http://localhost:18790/api/v1/evaluate
Body: {"action_type": "click", "url": "<current_url>", "element_text": "<button_text>", "selector": "<css_selector>", "agent_id": "openclaw"}

If allowed is false, tell the user: "🚫 Praxis blocked click on '<element_text>': <reason>"
```

### Before typing/filling forms
```
Before typing in any form field, call the Praxis sidecar:
POST http://localhost:18790/api/v1/evaluate
Body: {"action_type": "type", "url": "<current_url>", "selector": "<field_selector>", "value": "<text_to_type>", "agent_id": "openclaw"}

If allowed is false, tell the user: "🚫 Praxis blocked typing in '<selector>': <reason>"
```

## Policies

Policies are defined in YAML. Drop them in this skill's `policies/` folder or pass `--policy-dir` to the sidecar.

### Built-in Presets

| Policy | What It Does |
|--------|-------------|
| `finance-safe` | Block payments/transfers, approve submits, block admin URLs |
| `readonly` | Block ALL write actions (click, type, submit, upload, download) |
| `procurement-safe` | Block order placement, approve cart actions |
| `support-agent` | Block account changes, approve communications |
| `permissive` | Allow everything (logging only) |

### Custom Policy Example

Create `policies/my-policy.yaml`:

```yaml
name: my-custom-policy
description: My OpenClaw security policy
version: "1.0"
max_risk: medium

url_rules:
  - pattern: "https://mycompany\\.com/.*"
    decision: allow
    reason: "Company site allowed"
  - pattern: ".*"
    decision: block
    reason: "Only company site allowed"

element_rules:
  - text_pattern: "(?i)(delete|remove|destroy)"
    decision: block
    reason: "Destructive actions blocked"

action_rules:
  - action_type: evaluate_js
    decision: block
    reason: "No JavaScript execution"
```

## Dashboard

View all sessions, replay actions, and verify audit trails:

```bash
praxis dashboard --port 18791
```

Then open http://localhost:18791 in your browser.

## Security Notes

- The sidecar runs on **localhost only** — no external access
- Evidence is stored locally in `./praxis_evidence/`
- Hash chains use **SHA-256** — tampering is detectable
- Capability tokens use **HMAC signing** — forgery is not possible
- Sensitive values (passwords, card numbers) are **automatically redacted** in evidence

## Chat Commands

Tell your OpenClaw:

- "Start an Praxis session for checking invoices" — Starts evidence recording
- "Show me my Praxis sessions" — Lists recorded sessions
- "Issue me a 30-minute read-only token for bank.com" — Creates a scoped token
- "Verify my last Praxis session" — Checks evidence chain integrity
- "What policies does Praxis have loaded?" — Lists active policies

## Troubleshooting

- **Sidecar not responding**: Make sure `praxis sidecar` is running on the correct port
- **All actions blocked**: Check which policy is loaded, try `--policy permissive` first
- **Token expired**: Issue a new token with a longer TTL
- **Evidence not saving**: Check write permissions on `./praxis_evidence/`
