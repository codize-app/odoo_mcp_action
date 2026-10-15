"""Servidor de autorización OAuth 2.1 de los endpoints MCP.

El servidor de autorización es el propio Odoo, para que conectar un cliente
MCP no exija configurar nada en el cliente:

* el cliente se identifica con un *Client ID Metadata Document* (CIMD), es
  decir, su ``client_id`` es una URL que publica él mismo (Claude y Claude
  Code lo hacen así), o bien se registra dinámicamente (RFC 7591);
* el usuario autoriza con su sesión normal de Odoo, en una pantalla que
  muestra el host del cliente y la URL de retorno;
* el token queda ligado al endpoint MCP concreto mediante el parámetro
  ``resource`` (RFC 8707), así que un token de ``/mcp/ventas`` no sirve en
  ``/mcp/compras``.
"""

import json
import logging
import time
from urllib.parse import urlencode, urlsplit

from odoo import http
from odoo.http import request

from ..models.mcp_oauth import (
    ACCESS_TOKEN_LIFETIME,
    AUTH_GROUP_PARAM,
    DCR_MAX_CLIENTS,
    DEFAULT_AUTH_GROUP,
    DEFAULT_AUTH_METHOD,
    MCP_SCOPE,
    MCP_SCOPES_SUPPORTED,
    REFRESH_TOKEN_LIFETIME,
    McpOauthError,
    is_loopback_redirect_uri,
    is_valid_redirect_uri,
    normalize_resource,
    origin_of,
    parse_scope,
)
from .mcp_discovery import (
    MCP_OAUTH_ROOT,
    MCP_ROOT,
    mcp_authorization_server_metadata,
    mcp_base_url,
)

_logger = logging.getLogger(__name__)

CONSENT_TEMPLATE = "odoo_mcp_action.mcp_oauth_consent"
ERROR_TEMPLATE = "odoo_mcp_action.mcp_oauth_error"
AUTH_METHODS_SUPPORTED = (DEFAULT_AUTH_METHOD, "client_secret_post")


class McpOauthController(http.Controller):
    # ------------------------------------------------------------------
    # Descubrimiento (RFC 8414)
    # ------------------------------------------------------------------
    @http.route(
        "/.well-known/oauth-authorization-server",
        type="http",
        auth="none",
        methods=["GET"],
        csrf=False,
    )
    def authorization_server_metadata(self, **kwargs):
        return request.make_json_response(mcp_authorization_server_metadata())

    # ------------------------------------------------------------------
    # Autorización (RFC 6749 §4.1, PKCE obligatorio)
    # ------------------------------------------------------------------
    @http.route(
        f"{MCP_OAUTH_ROOT}/authorize",
        type="http",
        auth="user",
        methods=["GET", "POST"],
        csrf=True,
        readonly=False,
    )
    def authorize(self, **kwargs):
        # Parámetros de la URL (GET) o del formulario (POST); el formulario
        # tiene prioridad.
        args = request.httprequest.args
        form = request.httprequest.form
        params = {key: args[key] for key in args}
        params.update({key: form[key] for key in form})
        # Cliente y redirección: si no son de confianza no se redirige a
        # ningún sitio, se muestra el error en una página (RFC 6749 §4.1.2.1).
        try:
            client, redirect_uri = self._validated_client(params)
        except McpOauthError as error:
            return self._error_page(error)
        state = params.get("state")
        # A partir de aquí la redirección es legítima y los errores vuelven
        # al cliente como parámetros de la respuesta de autorización.
        try:
            resource, scopes, code_challenge = self._validated_request(
                params, redirect_uri
            )
        except McpOauthError as error:
            return self._redirect_error(redirect_uri, error, state)
        if not self._may_authorize():
            return self._error_page(
                McpOauthError(
                    "access_denied",
                    "Su usuario no pertenece al grupo autorizado a conectar "
                    "clientes MCP.",
                )
            )
        if request.httprequest.method == "POST":
            if params.get("decision") != "allow":
                return self._redirect_error(
                    redirect_uri,
                    McpOauthError("access_denied", "El usuario ha denegado el acceso."),
                    state,
                )
            code = (
                request.env["mcp.oauth.code"]
                .sudo()
                ._mcp_issue(
                    client_id=client.client_id,
                    redirect_uri=redirect_uri,
                    code_challenge=code_challenge,
                    scope=" ".join(scopes),
                    resource=resource,
                    user=request.env.user,
                )
            )
            return self._redirect(redirect_uri, {"code": code, "state": state})
        return request.render(
            CONSENT_TEMPLATE,
            self._consent_values(client, params, resource, scopes, redirect_uri),
        )

    # ------------------------------------------------------------------
    # Token (RFC 6749 §4.1.3 y §6)
    # ------------------------------------------------------------------
    @http.route(
        f"{MCP_OAUTH_ROOT}/token",
        type="http",
        auth="none",
        methods=["POST"],
        csrf=False,
        readonly=False,
    )
    def token(self, **kwargs):
        if request.httprequest.mimetype != "application/x-www-form-urlencoded":
            return self._token_error(
                "invalid_request",
                "El cuerpo debe enviarse como "
                "«application/x-www-form-urlencoded».",
            )
        params = request.httprequest.form
        client = (
            request.env["mcp.oauth.client"]
            .sudo()
            .search([("client_id", "=", (params.get("client_id") or "").strip())], limit=1)
        )
        if not client or not client._mcp_check_secret(params.get("client_secret")):
            return self._token_error(
                "invalid_client", "Cliente OAuth no válido.", status=401
            )
        grant_type = params.get("grant_type")
        try:
            if grant_type == "authorization_code":
                return self._exchange_code(client, params)
            if grant_type == "refresh_token":
                return self._refresh_access_token(client, params)
        except McpOauthError as error:
            return self._token_error(error.error, error.description)
        return self._token_error(
            "unsupported_grant_type",
            f"Tipo de concesión no admitido: {grant_type}",
        )

    # ------------------------------------------------------------------
    # Registro dinámico (RFC 7591): los clientes que no publican un CIMD
    # ------------------------------------------------------------------
    @http.route(
        f"{MCP_OAUTH_ROOT}/register",
        type="http",
        auth="none",
        methods=["POST"],
        csrf=False,
        readonly=False,
    )
    def register(self, **kwargs):
        clients = request.env["mcp.oauth.client"].sudo()
        if clients._mcp_dynamic_client_count() >= DCR_MAX_CLIENTS:
            return self._token_error(
                "temporarily_unavailable",
                "Hay demasiados clientes registrados; elimine los que ya no "
                "se usen desde Ajustes → Técnico.",
                status=429,
            )
        try:
            payload = json.loads(request.httprequest.data.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            return self._token_error(
                "invalid_client_metadata", "El cuerpo no es JSON válido."
            )
        if not isinstance(payload, dict):
            return self._token_error(
                "invalid_client_metadata", "El cuerpo debe ser un objeto JSON."
            )
        redirect_uris = payload.get("redirect_uris")
        if (
            not isinstance(redirect_uris, list)
            or not redirect_uris
            or not all(isinstance(uri, str) for uri in redirect_uris)
        ):
            return self._token_error(
                "invalid_redirect_uri", "Falta la lista «redirect_uris»."
            )
        for uri in redirect_uris:
            if not is_valid_redirect_uri(uri):
                return self._token_error(
                    "invalid_redirect_uri", f"«redirect_uri» no admitida: {uri}"
                )
        auth_method = payload.get("token_endpoint_auth_method") or DEFAULT_AUTH_METHOD
        if auth_method not in AUTH_METHODS_SUPPORTED:
            return self._token_error(
                "invalid_client_metadata",
                f"Método de autenticación no admitido: {auth_method}",
            )
        name = payload.get("client_name")
        client, secret = clients._mcp_register_client(
            name if isinstance(name, str) else None, redirect_uris, auth_method
        )
        body = {
            "client_id": client.client_id,
            "client_id_issued_at": int(time.time()),
            "client_name": client.name,
            "redirect_uris": redirect_uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": auth_method,
        }
        if secret:
            body["client_secret"] = secret
        return request.make_json_response(
            body, headers={"Cache-Control": "no-store"}, status=201
        )

    # ------------------------------------------------------------------
    # Canje de código y refresco
    # ------------------------------------------------------------------
    def _exchange_code(self, client, params):
        code = (
            request.env["mcp.oauth.code"]
            .sudo()
            ._mcp_redeem(
                params.get("code"), client.client_id, params.get("redirect_uri")
            )
        )
        if not code:
            raise McpOauthError(
                "invalid_grant", "Código de autorización no válido o caducado."
            )
        if not request.env["mcp.oauth.code"]._mcp_verify_pkce(
            params.get("code_verifier"), code["code_challenge"]
        ):
            raise McpOauthError(
                "invalid_grant",
                "El «code_verifier» no corresponde al «code_challenge».",
            )
        resource = (params.get("resource") or "").strip().rstrip("/")
        if resource and resource != code["resource"]:
            raise McpOauthError(
                "invalid_target",
                "El «resource» no coincide con el de la autorización.",
            )
        return self._issue_tokens(
            client, code["user"], code["scope"], code["resource"]
        )

    def _refresh_access_token(self, client, params):
        record = (
            request.env["mcp.oauth.token"]
            .sudo()
            ._mcp_redeem_refresh(params.get("refresh_token"), client.client_id)
        )
        if not record:
            raise McpOauthError(
                "invalid_grant", "Token de refresco no válido o caducado."
            )
        granted = parse_scope(record.scope)
        requested = parse_scope(params.get("scope")) or granted
        if not set(requested) <= set(granted):
            raise McpOauthError(
                "invalid_scope", "No se pueden ampliar los ámbitos ya concedidos."
            )
        return self._issue_tokens(
            client, record.user_id, " ".join(requested), record.resource
        )

    def _issue_tokens(self, client, user, scope, resource):
        """Emite el par de tokens; el de refresco se rota en cada uso."""
        tokens = request.env["mcp.oauth.token"].sudo()
        access_token = tokens._mcp_issue(
            "access", client.client_id, user, scope, resource, ACCESS_TOKEN_LIFETIME
        )
        refresh_token = tokens._mcp_issue(
            "refresh", client.client_id, user, scope, resource, REFRESH_TOKEN_LIFETIME
        )
        return request.make_json_response(
            {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": int(ACCESS_TOKEN_LIFETIME.total_seconds()),
                "refresh_token": refresh_token,
                "scope": scope,
            },
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    # ------------------------------------------------------------------
    # Validaciones de la petición de autorización
    # ------------------------------------------------------------------
    @staticmethod
    def _validated_client(params):
        """Cliente del ``client_id`` y comprobación de la ``redirect_uri``."""
        client_id = (params.get("client_id") or "").strip()
        client = (
            request.env["mcp.oauth.client"].sudo()._mcp_resolve_client(client_id)
        )
        if not client:
            raise McpOauthError(
                "invalid_client",
                "Cliente OAuth desconocido o documento de metadatos "
                "no disponible.",
            )
        redirect_uri = params.get("redirect_uri") or ""
        if not client._mcp_allows_redirect(redirect_uri):
            raise McpOauthError(
                "invalid_request",
                "La «redirect_uri» no está registrada para este cliente.",
            )
        return client, redirect_uri

    @staticmethod
    def _validated_request(params, redirect_uri):
        """Resto de parámetros: tipo de respuesta, PKCE, ámbitos y recurso."""
        if params.get("response_type") != "code":
            raise McpOauthError(
                "unsupported_response_type", "Solo se admite response_type=code."
            )
        code_challenge = params.get("code_challenge") or ""
        if params.get("code_challenge_method") != "S256" or not code_challenge:
            raise McpOauthError(
                "invalid_request",
                "Se requiere PKCE con code_challenge_method=S256.",
            )
        scopes = list(dict.fromkeys(parse_scope(params.get("scope")) or [MCP_SCOPE]))
        if MCP_SCOPE not in scopes:
            raise McpOauthError(
                "invalid_scope", f"Falta el ámbito «{MCP_SCOPE}»."
            )
        unsupported = sorted(set(scopes) - set(MCP_SCOPES_SUPPORTED))
        if unsupported:
            raise McpOauthError(
                "invalid_scope", "Ámbitos no admitidos: " + ", ".join(unsupported)
            )
        return (
            McpOauthController._validated_resource(params.get("resource")),
            scopes,
            code_challenge,
        )

    @staticmethod
    def _validated_resource(value):
        """El recurso debe ser un endpoint MCP real de este mismo Odoo."""
        resource = normalize_resource((value or "").strip())
        if not resource:
            raise McpOauthError(
                "invalid_request",
                "Falta el parámetro «resource» o no es una URL válida "
                "(RFC 8707).",
            )
        prefix = f"{MCP_ROOT}/"
        parts = urlsplit(resource)
        route = parts.path[len(prefix):] if parts.path.startswith(prefix) else ""
        if not route or "/" in route:
            raise McpOauthError(
                "invalid_target", "El recurso no es un endpoint MCP de Odoo."
            )
        if origin_of(resource) != origin_of(mcp_base_url()):
            raise McpOauthError(
                "invalid_target", "El recurso pertenece a otro servidor."
            )
        if not request.env["ir.actions.server"].sudo()._mcp_route_exists(route):
            raise McpOauthError(
                "invalid_target", f"No existe el endpoint MCP «{route}»."
            )
        return resource

    # ------------------------------------------------------------------
    # Consentimiento
    # ------------------------------------------------------------------
    @staticmethod
    def _may_authorize():
        """Solo el grupo configurado puede autorizar clientes.

        El código de las acciones se ejecuta como superusuario, así que por
        defecto la autorización queda para los administradores; el parámetro
        de sistema ``mcp_server_action.auth_group`` permite abrirla a otro
        grupo (por ejemplo, un grupo de integraciones).
        """
        group = McpOauthController._authorized_group()
        return bool(group) and group in request.env.user.group_ids

    @staticmethod
    def _authorized_group():
        value = (
            request.env["ir.config_parameter"]
            .sudo()
            .get_param(AUTH_GROUP_PARAM, DEFAULT_AUTH_GROUP)
            or ""
        ).strip()
        if not value:
            return request.env["res.groups"].browse()
        if value.isdigit():
            return request.env["res.groups"].sudo().browse(int(value)).exists()
        group = request.env.ref(value, raise_if_not_found=False)
        if not group or group._name != "res.groups":
            _logger.warning(
                "MCP: el grupo «%s» de %s no existe; nadie puede autorizar",
                value,
                AUTH_GROUP_PARAM,
            )
            return request.env["res.groups"].browse()
        return group

    @staticmethod
    def _consent_values(client, params, resource, scopes, redirect_uri):
        """Contexto de la pantalla de consentimiento.

        Se muestra el host del ``client_id`` (dato que el cliente no puede
        falsificar) y el host de retorno, como exige el CIMD §6.4 y la
        especificación de autorización de MCP.
        """
        parts = urlsplit(redirect_uri)
        return {
            "client": client,
            "client_host": client._mcp_client_host(),
            "client_name": client.name,
            "redirect_uri": redirect_uri,
            "redirect_host": parts.hostname or redirect_uri,
            "resource": resource,
            "scopes": scopes,
            "csrf_token": request.csrf_token(),
            "user": request.env.user,
            "loopback_only": all(
                is_loopback_redirect_uri(uri) for uri in client._mcp_redirect_uris()
            ),
            "hidden": [
                (key, value)
                for key, value in params.items()
                if key not in ("decision", "csrf_token")
            ],
        }

    # ------------------------------------------------------------------
    # Respuestas
    # ------------------------------------------------------------------
    @staticmethod
    def _redirect(redirect_uri, values):
        query = urlencode(
            {key: value for key, value in values.items() if value not in (None, "")}
        )
        separator = "&" if urlsplit(redirect_uri).query else "?"
        return request.make_response(
            "",
            headers={"Location": f"{redirect_uri}{separator}{query}"},
            status=302,
        )

    def _redirect_error(self, redirect_uri, error, state):
        return self._redirect(
            redirect_uri,
            {
                "error": error.error,
                "error_description": error.description,
                "state": state,
            },
        )

    @staticmethod
    def _error_page(error):
        return request.render(
            ERROR_TEMPLATE,
            {"error": error.error, "description": error.description},
            status=400,
            headers={"Cache-Control": "no-store"},
        )

    @staticmethod
    def _token_error(error, description, status=400):
        return request.make_json_response(
            {"error": error, "error_description": description},
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
            status=status,
        )
