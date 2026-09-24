"""
Praxis Lite — the on-device guardrail for agentic AI.

Praxis sits between the AI tools you already use (Claude, Codex/ChatGPT,
Cursor, any MCP client) and your machine. Before an agent reads a file,
deletes something, or runs an action, Praxis checks it against your
policy and decides: allow, block, or ask you first.

This is the free, MIT-licensed Lite edition: the on-device MCP
filesystem guardrail, the principal + risk-tier policy engine, the
tamper-proof evidence log, offline (Ollama) support, and the daemon.

Core modules:
    - principal:   who is asking (praxis:local vs agent:*)
    - tiers:       risk tiers T0-T3
    - policy:      allow / block / ask decisions
    - filesystem:  guarded search / read / delete + recoverable trash
    - evidence:    tamper-proof hash-chained audit log
    - mcp:         the MCP server AI tools connect to
    - daemon:      the background guardrail service
    - llm:         offline local-model (Ollama) support
"""

__version__ = "0.2.1"

from praxis.policy.engine import Policy, PolicyEngine
from praxis.evidence.vault import EvidenceVault
from praxis.tokens.capability import CapabilityToken
from praxis.principal import Principal, PrincipalResolver

__all__ = [
    "Policy",
    "PolicyEngine",
    "EvidenceVault",
    "CapabilityToken",
    "Principal",
    "PrincipalResolver",
]
