"""
URLs públicas y documentos de descubrimiento OAuth de los endpoints MCP.

Servidor de autorización (RFC 9728 y RFC 8414)
"""

from odoo.http import request

from ..models.mcp_oauth import (
    MCP_SCOPES_SUPPORTED,
    PUBLIC_BASE_URL_PARAM,
    normalize_resource,
)

MCP_ROOT = "/mcp"
MCP_OAUTH_ROOT = "/mcp/oauth"
PROTECTED_RESOURCE_WELL_KNOWN = "/.well-known/oauth-protected-resource"

def mcp_base_url():
    configured = (
        request.env["ir.config_parameter"].sudo().get_param(PUBLIC_BASE_URL_PARAM)
    )
    if configured and configured.strip():
        return configured.strip().rstrip("/")
    return request.httprequest.root_url.rstrip("/")

def mcp_resource_url(route):
    url = f"{mcp_base_url()}{MCP_ROOT}/{route}"
    return normalize_resource(url) or url

def mcp_protected_resource_metadata_url(route):
    return (
        f"{mcp_base_url()}{PROTECTED_RESOURCE_WELL_KNOWN}{MCP_ROOT}/{route}"
    )

def mcp_protected_resource_metadata(route):
    return {
        "resource": mcp_resource_url(route),
        "authorization_servers": [mcp_base_url()],
        "scopes_supported": list(MCP_SCOPES_SUPPORTED),
        "bearer_methods_supported": ["header"],
        "resource_name": f"Odoo MCP ({route})",
    }

def mcp_authorization_server_metadata():
    base_url = mcp_base_url()
    return {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}{MCP_OAUTH_ROOT}/authorize",
        "token_endpoint": f"{base_url}{MCP_OAUTH_ROOT}/token",
        "registration_endpoint": f"{base_url}{MCP_OAUTH_ROOT}/register",
        "scopes_supported": list(MCP_SCOPES_SUPPORTED),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
        "client_id_metadata_document_supported": True,
    }
