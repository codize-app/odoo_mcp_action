"""Modelos OAuth 2.1 que dan soporte a los endpoints MCP.

El módulo hace a la vez de servidor de recursos (los endpoints
``/mcp/<ruta>``) y de servidor de autorización: publica metadatos de
recurso protegido (RFC 9728) y de servidor de autorización (RFC 8414),
acepta clientes identificados con un *Client ID Metadata Document*
(CIMD, ``client_id`` con forma de URL) y también clientes registrados
dinámicamente (RFC 7591), y emite tokens de acceso ligados al recurso
(RFC 8707) con rotación de tokens de refresco.
"""

import base64
import hashlib
import ipaddress
import logging
import socket
import secrets
from datetime import timedelta
from urllib.parse import urlsplit

import requests

from odoo import api, fields, models

_logger = logging.getLogger(__name__)

#: Ámbito que protege los endpoints MCP.
MCP_SCOPE = "mcp"
#: Ámbito que los clientes piden para obtener token de refresco.
OFFLINE_ACCESS_SCOPE = "offline_access"
MCP_SCOPES_SUPPORTED = (MCP_SCOPE, OFFLINE_ACCESS_SCOPE)

ACCESS_TOKEN_LIFETIME = timedelta(hours=1)
REFRESH_TOKEN_LIFETIME = timedelta(days=30)
AUTHORIZATION_CODE_LIFETIME = timedelta(minutes=5)
PURGE_GRACE = timedelta(days=1)

#: Parámetro de sistema con la URL pública base del servidor Odoo.
PUBLIC_BASE_URL_PARAM = "mcp_server_action.public_base_url"
#: Parámetro de sistema con el grupo cuyos usuarios pueden autorizar clientes.
AUTH_GROUP_PARAM = "mcp_server_action.auth_group"
DEFAULT_AUTH_GROUP = "base.group_system"

#: Límites de caché de los documentos CIMD (RFC 9111).
CIMD_DEFAULT_CACHE = 3600
CIMD_MIN_CACHE = 300
CIMD_MAX_CACHE = 86400
CIMD_MAX_BYTES = 16 * 1024
CIMD_TIMEOUT = 5

#: Hosts de bucle local: su puerto es efímero (RFC 8252 §7.3).
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

#: Tope de clientes registrados dinámicamente, para acotar el abuso.
DCR_MAX_CLIENTS = 1000

DEFAULT_AUTH_METHOD = "none"


class McpOauthError(Exception):
    """Error de protocolo OAuth, con el código y el texto a devolver.

    El código sigue RFC 6749 §5.2 (``invalid_client``, ``invalid_grant``,
    ``invalid_scope``, ``invalid_target``…).
    """

    def __init__(self, error, description):
        super().__init__(description)
        self.error = error
        self.description = description


def hash_secret(value):
    """Hash de códigos, tokens y secretos: nunca se guardan en claro."""
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()


def bearer_token(authorization):
    """Token de un header ``Authorization: Bearer <token>``, o None."""
    scheme, _, value = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()


def parse_scope(value):
    """Lista de ámbitos de un parámetro ``scope``."""
    return [scope for scope in (value or "").split() if scope]


def split_url(url):
    """``urlsplit`` tolerante: None si la URL no es absoluta o es inválida."""
    try:
        parts = urlsplit(url or "")
        if not parts.scheme or not parts.hostname:
            return None
        parts.port  # fuerza la validación del puerto
    except ValueError:
        return None
    return parts


def is_client_id_url(client_id):
    """Los ``client_id`` con esquema http(s) se resuelven como documento CIMD."""
    return urlsplit(client_id or "").scheme in ("http", "https")


def origin_of(url):
    """Origen (esquema://host[:puerto]) de una URL, o None."""
    parts = split_url(url)
    if not parts:
        return None
    default_port = {"https": 443, "http": 80}.get(parts.scheme)
    port = parts.port
    suffix = f":{port}" if port and port != default_port else ""
    return f"{parts.scheme}://{parts.hostname}{suffix}"

def normalize_resource(url):
    """Identificador canónico de recurso (RFC 8707 §2).

    Esquema y host en minúsculas, sin puerto por defecto ni barra final, de
    modo que el ``resource`` que envía el cliente y el que calcula el
    endpoint MCP coincidan aunque cambien las mayúsculas. Devuelve None si
    la URL no sirve como recurso (p. ej. con fragmento o consulta).
    """
    parts = split_url(url)
    if not parts or parts.fragment or parts.query:
        return None
    return f"{origin_of(url)}{parts.path.rstrip('/')}"


def is_loopback_redirect_uri(url):
    """True para redirecciones de bucle local (``http://localhost/…``)."""
    parts = split_url(url)
    return bool(parts) and parts.scheme == "http" and parts.hostname in LOOPBACK_HOSTS


def is_valid_redirect_uri(url):
    """Solo HTTPS o HTTP en bucle local (OAuth 2.1 §1.5, RFC 8252)."""
    parts = split_url(url)
    if not parts or parts.fragment:
        return False
    if parts.scheme == "https":
        return True
    return parts.scheme == "http" and parts.hostname in LOOPBACK_HOSTS


def redirect_uri_matches(requested, registered):
    """Coteja la ``redirect_uri`` pedida con una registrada.

    Comparación exacta (RFC 9700 §3.1) salvo por el puerto en redirecciones
    de bucle local, que es efímero en clientes nativos (RFC 8252 §7.3); los
    clientes de Claude declaran ``http://localhost/callback`` y
    ``http://127.0.0.1/callback`` sin puerto.
    """
    if not requested or not registered:
        return False
    if requested == registered:
        return True
    if not (
        is_loopback_redirect_uri(requested)
        and is_loopback_redirect_uri(registered)
    ):
        return False
    req, reg = split_url(requested), split_url(registered)
    return (
        req.hostname == reg.hostname
        and req.path == reg.path
        and req.query == reg.query
    )


def is_fetchable_client_id_url(client_id):
    """Comprueba que el ``client_id`` sea una URL HTTPS pública.

    Aplica las restricciones de CIMD §3 (HTTPS, con componente de ruta, sin
    fragmento, usuario, contraseña ni segmentos ``.``/``..``) y resuelve el
    nombre de host para descartar destinos internos (SSRF, CIMD §6.5).
    """
    parts = split_url(client_id)
    if not parts or parts.scheme != "https":
        return False
    if parts.username or parts.password or parts.fragment or parts.query:
        return False
    segments = [segment for segment in parts.path.split("/") if segment]
    if not segments or any(segment in (".", "..") for segment in segments):
        return False
    try:
        addresses = {
            info[4][0]
            for info in socket.getaddrinfo(
                parts.hostname, parts.port or 443, proto=socket.IPPROTO_TCP
            )
        }
    except OSError:
        return False
    if not addresses:
        return False
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address.split("%")[0])
        except ValueError:
            return False
        if not ip.is_global:
            return False
    return True


def cache_seconds(cache_control):
    """Vida útil de la caché del documento CIMD según sus cabeceras HTTP."""
    for directive in (cache_control or "").split(","):
        name, _, value = directive.strip().partition("=")
        name = name.lower()
        if name in ("no-store", "no-cache"):
            return CIMD_MIN_CACHE
        if name == "max-age":
            try:
                return min(
                    max(int(value.strip('" ')), CIMD_MIN_CACHE), CIMD_MAX_CACHE
                )
            except ValueError:
                break
    return CIMD_DEFAULT_CACHE


def pkce_challenge(verifier):
    """``code_challenge`` S256 (RFC 7636 §4.2) de un ``code_verifier``."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class McpOauthClient(models.Model):
    _name = "mcp.oauth.client"
    _description = "Cliente OAuth de los endpoints MCP"
    _order = "name, id"

    name = fields.Char(string="Nombre", required=True)
    client_id = fields.Char(
        string="Client ID",
        required=True,
        index=True,
        help="Identificador del cliente; una URL cuando proviene de un "
             "Client ID Metadata Document.",
    )
    is_cimd = fields.Boolean(
        string="Client ID Metadata Document",
        help="El «client_id» es una URL cuyo documento publica el propio "
             "cliente, así que no hubo registro previo.",
    )
    redirect_uris = fields.Text(
        string="URLs de redirección", help="Una por línea."
    )
    token_endpoint_auth_method = fields.Selection(
        [
            ("none", "Cliente público (PKCE)"),
            ("client_secret_post", "Secreto de cliente"),
        ],
        string="Autenticación en /token",
        required=True,
        default=DEFAULT_AUTH_METHOD,
    )
    secret_hash = fields.Char(string="Hash del secreto")
    metadata_expires_at = fields.Datetime(
        string="Caduca la caché del documento",
        help="Momento en que se volverá a leer el documento del cliente.",
    )

    _client_id_unique = models.Constraint(
        "UNIQUE(client_id)", "Ese «client_id» ya está registrado."
    )

    def _mcp_redirect_uris(self):
        self.ensure_one()
        return [
            uri.strip()
            for uri in (self.redirect_uris or "").splitlines()
            if uri.strip()
        ]

    def _mcp_client_host(self):
        """Host que se muestra al usuario: el del ``client_id`` es lo único
        que el cliente no puede falsificar por sí mismo."""
        self.ensure_one()
        parts = split_url(self.client_id)
        return parts.hostname if parts else self.name

    def _mcp_allows_redirect(self, redirect_uri):
        self.ensure_one()
        return any(
            redirect_uri_matches(redirect_uri, registered)
            for registered in self._mcp_redirect_uris()
        )

    def _mcp_check_secret(self, secret):
        """Valida el secreto; los clientes públicos no envían ninguno."""
        self.ensure_one()
        if self.token_endpoint_auth_method == "none":
            return True
        return bool(secret) and bool(self.secret_hash) and secrets.compare_digest(
            hash_secret(secret), self.secret_hash
        )

    @api.model
    def _mcp_resolve_client(self, client_id):
        """Cliente de ese ``client_id``, leyendo su documento si es una URL.

        Devuelve un recordset vacío si el cliente no existe y no se puede
        descubrir. Lanza :class:`McpOauthError` si el documento existe pero
        es inválido.
        """
        if not client_id:
            return self.browse()
        if not is_client_id_url(client_id):
            return self.search([("client_id", "=", client_id)], limit=1)
        client = self.search([("client_id", "=", client_id)], limit=1)
        now = fields.Datetime.now()
        if client.is_cimd and client.metadata_expires_at and (
            client.metadata_expires_at > now
        ):
            return client
        metadata = self._mcp_fetch_client_metadata(client_id)
        if metadata is None:
            # Fallo de red: se sigue usando la última copia válida.
            _logger.warning(
                "MCP: no se pudo refrescar el documento del cliente %s",
                client_id,
            )
            return client
        values = {
            "name": metadata["name"],
            "redirect_uris": "\n".join(metadata["redirect_uris"]),
            "token_endpoint_auth_method": DEFAULT_AUTH_METHOD,
            "is_cimd": True,
            "metadata_expires_at": now
            + timedelta(seconds=metadata["cache_seconds"]),
        }
        if client:
            client.write(values)
            return client
        return self.create(dict(values, client_id=client_id))

    @api.model
    def _mcp_fetch_client_metadata(self, client_id):
        """Descarga y valida el Client ID Metadata Document.

        Devuelve ``{"name", "redirect_uris", "cache_seconds"}``, None si el
        documento no se pudo obtener, y lanza :class:`McpOauthError` si se
        obtuvo pero no cumple CIMD §4.
        """
        if not is_fetchable_client_id_url(client_id):
            raise McpOauthError(
                "invalid_client",
                "El «client_id» no es una URL HTTPS pública válida.",
            )
        try:
            response = requests.get(
                client_id,
                timeout=CIMD_TIMEOUT,
                headers={"Accept": "application/json"},
                allow_redirects=False,
            )
        except requests.RequestException as error:
            _logger.warning("MCP: error al leer el CIMD %s: %s", client_id, error)
            return None
        if response.status_code != 200:
            _logger.warning(
                "MCP: el CIMD %s respondió %s", client_id, response.status_code
            )
            return None
        if len(response.content) > CIMD_MAX_BYTES:
            raise McpOauthError(
                "invalid_client",
                "El documento de metadatos del cliente es demasiado grande.",
            )
        try:
            document = response.json()
        except ValueError:
            raise McpOauthError(
                "invalid_client",
                "El documento de metadatos del cliente no es JSON válido.",
            )
        if not isinstance(document, dict) or document.get("client_id") != client_id:
            raise McpOauthError(
                "invalid_client",
                "El documento de metadatos no declara ese mismo «client_id».",
            )
        if (document.get("token_endpoint_auth_method") or DEFAULT_AUTH_METHOD) != (
            DEFAULT_AUTH_METHOD
        ):
            raise McpOauthError(
                "invalid_client",
                "El documento del cliente usa un método de autenticación "
                "no admitido (no puede tener secreto).",
            )
        redirect_uris = document.get("redirect_uris")
        if (
            not isinstance(redirect_uris, list)
            or not redirect_uris
            or not all(isinstance(uri, str) for uri in redirect_uris)
        ):
            raise McpOauthError(
                "invalid_client",
                "El documento de metadatos no declara «redirect_uris».",
            )
        client_origin = origin_of(client_id)
        for uri in redirect_uris:
            if not is_valid_redirect_uri(uri):
                raise McpOauthError(
                    "invalid_client",
                    f"«redirect_uri» no admitida: {uri}",
                )
            if not is_loopback_redirect_uri(uri) and origin_of(uri) != client_origin:
                raise McpOauthError(
                    "invalid_client",
                    "Las «redirect_uris» deben compartir el origen del "
                    "«client_id».",
                )
        name = document.get("client_name")
        if not isinstance(name, str) or not name.strip():
            name = split_url(client_id).hostname
        return {
            "name": name.strip(),
            "redirect_uris": redirect_uris,
            "cache_seconds": cache_seconds(response.headers.get("Cache-Control")),
        }

    @api.model
    def _mcp_register_client(self, client_name, redirect_uris, auth_method):
        """Registra un cliente nuevo (RFC 7591).

        Devuelve ``(cliente, secreto)``; el secreto solo se devuelve una vez
        y se guarda su hash.
        """
        values = {
            "name": client_name or "Cliente OAuth",
            "redirect_uris": "\n".join(redirect_uris),
            "token_endpoint_auth_method": auth_method,
            "is_cimd": False,
            "metadata_expires_at": False,
        }
        secret = None
        if auth_method != DEFAULT_AUTH_METHOD:
            secret = secrets.token_urlsafe(48)
            values["secret_hash"] = hash_secret(secret)
        return self.create(values), secret

    @api.model
    def _mcp_dynamic_client_count(self):
        return self.search_count([("is_cimd", "=", False)])


class McpOauthCode(models.Model):
    _name = "mcp.oauth.code"
    _description = "Código de autorización OAuth de MCP"

    code_hash = fields.Char(string="Hash del código", required=True, index=True)
    client_id = fields.Char(string="Client ID", required=True)
    redirect_uri = fields.Char(string="URL de redirección", required=True)
    code_challenge = fields.Char(string="Code challenge", required=True)
    scope = fields.Char(string="Ámbitos")
    resource = fields.Char(string="Recurso", required=True, index=True)
    user_id = fields.Many2one(
        "res.users",
        string="Usuario",
        required=True,
        ondelete="cascade",
        index=True,
    )
    expires_at = fields.Datetime(string="Caduca el", required=True)

    @api.model
    def _mcp_issue(self, client_id, redirect_uri, code_challenge, scope, resource, user):
        """Emite un código de autorización de un solo uso."""
        self._mcp_purge()
        code = secrets.token_urlsafe(32)
        self.create(
            {
                "code_hash": hash_secret(code),
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_challenge": code_challenge,
                "scope": scope,
                "resource": resource,
                "user_id": user.id,
                "expires_at": fields.Datetime.now() + AUTHORIZATION_CODE_LIFETIME,
            }
        )
        return code

    @api.model
    def _mcp_redeem(self, code, client_id, redirect_uri):
        """Consume el código y devuelve sus datos, o un dict vacío.

        Un código solo sirve una vez y solo para el cliente y la
        redirección que lo pidieron (RFC 9700 §4.1).
        """
        record = self.search(
            [("code_hash", "=", hash_secret(code or ""))], limit=1
        )
        if not record or record.client_id != client_id:
            return {}
        if record.redirect_uri != redirect_uri:
            return {}
        if record.expires_at < fields.Datetime.now():
            record.unlink()
            return {}
        values = {
            "code_challenge": record.code_challenge,
            "scope": record.scope,
            "resource": record.resource,
            "user": record.user_id,
        }
        record.unlink()
        return values

    @staticmethod
    def _mcp_verify_pkce(code_verifier, code_challenge):
        """Comprueba el ``code_verifier`` contra el ``code_challenge`` S256."""
        if not code_verifier or not code_challenge:
            return False
        if not 43 <= len(code_verifier) <= 128:
            return False
        if not all(
            character.isalnum() or character in "-._~"
            for character in code_verifier
        ):
            return False
        return secrets.compare_digest(pkce_challenge(code_verifier), code_challenge)

    @api.model
    def _mcp_purge(self):
        """Elimina códigos caducados (limpieza oportunista)."""
        self.sudo().search(
            [("expires_at", "<", fields.Datetime.now() - PURGE_GRACE)]
        ).unlink()


class McpOauthToken(models.Model):
    _name = "mcp.oauth.token"
    _description = "Token OAuth de MCP"
    _order = "create_date desc, id desc"

    token_hash = fields.Char(string="Hash del token", required=True, index=True)
    kind = fields.Selection(
        [("access", "Acceso"), ("refresh", "Refresco")],
        string="Tipo",
        required=True,
        index=True,
    )
    client_id = fields.Char(string="Client ID", required=True, index=True)
    user_id = fields.Many2one(
        "res.users",
        string="Usuario",
        required=True,
        ondelete="cascade",
        index=True,
    )
    scope = fields.Char(string="Ámbitos")
    resource = fields.Char(string="Recurso", index=True)
    expires_at = fields.Datetime(string="Caduca el", required=True, index=True)
    revoked = fields.Boolean(
        string="Revocado",
        help="Los tokens de refresco se rotan en cada uso: el anterior queda "
             "revocado, y reutilizarlo revoca toda la familia.",
    )

    @api.model
    def _mcp_issue(self, kind, client_id, user, scope, resource, lifetime):
        """Emite un token y devuelve su valor en claro (solo aquí)."""
        self._mcp_purge()
        token = secrets.token_urlsafe(48)
        self.create(
            {
                "token_hash": hash_secret(token),
                "kind": kind,
                "client_id": client_id,
                "user_id": user.id,
                "scope": scope,
                "resource": resource,
                "expires_at": fields.Datetime.now() + lifetime,
            }
        )
        return token

    @api.model
    def _mcp_authenticate(self, authorization, resource):
        """Token de acceso válido para ese recurso, o recordset vacío.

        El token debe estar emitido para el recurso exacto al que se llama
        (RFC 8707: nunca se aceptan tokens de otro público) y pertenecer a
        un usuario activo.
        """
        token = bearer_token(authorization)
        if not token:
            return self.browse()
        record = self.search(
            [
                ("token_hash", "=", hash_secret(token)),
                ("kind", "=", "access"),
                ("revoked", "=", False),
                ("resource", "=", resource),
                ("user_id.active", "=", True),
            ],
            limit=1,
        )
        if not record or record.expires_at < fields.Datetime.now():
            return self.browse()
        if MCP_SCOPE not in parse_scope(record.scope):
            return self.browse()
        return record

    @api.model
    def _mcp_redeem_refresh(self, token, client_id):
        """Valida un token de refresco y lo rota (OAuth 2.1 §4.3.1).

        Devuelve el token si era válido; reutilizar uno ya rotado revoca
        todos los tokens de ese cliente para ese usuario.
        """
        record = self.search(
            [("token_hash", "=", hash_secret(token or "")), ("kind", "=", "refresh")],
            limit=1,
        )
        if not record or record.client_id != client_id:
            return self.browse()
        if record.revoked:
            _logger.warning(
                "MCP: token de refresco reutilizado por %s; se revocan sus tokens",
                client_id,
            )
            self.search(
                [("client_id", "=", client_id), ("user_id", "=", record.user_id.id)]
            ).write({"revoked": True})
            return self.browse()
        if record.expires_at < fields.Datetime.now():
            return self.browse()
        record.revoked = True
        return record

    @api.model
    def _mcp_purge(self):
        """Elimina tokens caducados hace tiempo (limpieza oportunista)."""
        self.sudo().search(
            [("expires_at", "<", fields.Datetime.now() - PURGE_GRACE)]
        ).unlink()
