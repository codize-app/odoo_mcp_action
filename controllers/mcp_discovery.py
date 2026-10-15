"""URLs públicas y documentos de descubrimiento OAuth de los endpoints MCP.

Los clientes MCP no saben nada de Odoo de antemano: descubren el servidor
de autorización leyendo estos documentos (RFC 9728 y RFC 8414), así que
todas las URLs se construyen a partir de la petición en curso para que
coincidan exactamente con la URL del endpoint que el usuario escribió en
su cliente.
"""

from odoo.http import request

from ..models.mcp_oauth import (
    MCP_SCOPES_SUPPORTED,
    PUBLIC_BASE_URL_PARAM,
    normalize_resource,
)

#: Prefijo de las rutas MCP (`/mcp/<ruta>`) y de su servidor de autorización.
MCP_ROOT = "/mcp"
MCP_OAUTH_ROOT = "/mcp/oauth"
PROTECTED_RESOURCE_WELL_KNOWN = "/.well-known/oauth-protected-resource"


def mcp_base_url():
    """URL pública base (esquema + host), sin barra final.

    Se deduce de la petición para que coincida con la URL que el cliente
    usó para llegar. El parámetro de sistema
    ``mcp_server_action.public_base_url`` permite fijarla cuando Odoo está
    detrás de un proxy que no reenvía el esquema original.
    """
    configured = (
        request.env["ir.config_parameter"].sudo().get_param(PUBLIC_BASE_URL_PARAM)
    )
    if configured and configured.strip():
        return configured.strip().rstrip("/")
    return request.httprequest.root_url.rstrip("/")


def mcp_resource_url(route):
    """Identificador canónico (RFC 8707) del endpoint MCP de esa ruta."""
    url = f"{mcp_base_url()}{MCP_ROOT}/{route}"
    return normalize_resource(url) or url


def mcp_protected_resource_metadata_url(route):
    """Dónde publica el endpoint su documento de recurso protegido."""
    return (
        f"{mcp_base_url()}{PROTECTED_RESOURCE_WELL_KNOWN}{MCP_ROOT}/{route}"
    )


def mcp_protected_resource_metadata(route):
    """Documento RFC 9728 del endpoint ``/mcp/<ruta>``."""
    return {
        "resource": mcp_resource_url(route),
        "authorization_servers": [mcp_base_url()],
        "scopes_supported": list(MCP_SCOPES_SUPPORTED),
        "bearer_methods_supported": ["header"],
        "resource_name": f"Odoo MCP ({route})",
    }


def mcp_authorization_server_metadata():
    """Documento RFC 8414 del servidor de autorización (el propio Odoo).

    Anuncia ``client_id_metadata_document_supported`` y ``none`` en
    ``token_endpoint_auth_methods_supported``: es la señal con la que los
    clientes (Claude, Claude Code) deciden identificarse con un Client ID
    Metadata Document en lugar de registrarse dinámicamente.
    """
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
