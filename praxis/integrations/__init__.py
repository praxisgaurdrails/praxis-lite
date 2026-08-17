"""Praxis client integrations — enable/disable Praxis in on-device AI tools."""

from praxis.integrations.clients import (
    KNOWN_CLIENTS,
    ClientStatus,
    ConfigFormat,
    MCPClient,
    build_server_spec,
    detect_clients,
    get_client,
)

__all__ = [
    "ClientStatus",
    "ConfigFormat",
    "KNOWN_CLIENTS",
    "MCPClient",
    "build_server_spec",
    "detect_clients",
    "get_client",
]
