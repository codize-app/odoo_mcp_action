"""
Servidor de recursos MCP
Endpoints generados como ``/mcp/<ruta>``.
"""

import json

from odoo import http
from odoo.http import request

from ..models.mcp_oauth import MCP_SCOPE
from .mcp_discovery import (
    MCP_ROOT,
    PROTECTED_RESOURCE_WELL_KNOWN,
    mcp_protected_resource_metadata,
    mcp_protected_resource_metadata_url,
    mcp_resource_url,
)

MCP_SERVER_INFO = {"name": "odoo-mcp-server-action", "version": "1.0.0"}
MCP_PROTOCOL_VERSION = "2025-11-25"

class McpController(http.Controller):
    @http.route(
        f"{MCP_ROOT}/<string:route>",
        type="http",
        auth="none",
        methods=["POST"],
        csrf=False,
        readonly=False,
    )
    def mcp_endpoint(self, route, **kwargs):
        try:
            payload = json.loads(request.httprequest.data.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            return self._error_response(
                None, -32700, "Error de sintaxis JSON", status=400
            )
        if not isinstance(payload, dict):
            return self._error_response(
                None, -32600, "Petición JSON-RPC no válida", status=400
            )
        # MCP
        if "id" not in payload:
            return request.make_response("", status=202)
        resource = mcp_resource_url(route)
        if not (
            request.env["mcp.oauth.token"]
            .sudo()
            ._mcp_authenticate(
                request.httprequest.headers.get("Authorization"), resource
            )
        ):
            return self._unauthorized(payload, route)
        method = payload.get("method")
        if method == "initialize":
            return request.make_json_response(
                self._result_response(
                    payload,
                    {
                        "protocolVersion": self._client_protocol_version(payload),
                        "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": MCP_SERVER_INFO,
                    },
                )
            )
        servers = request.env["ir.actions.server"].sudo()
        if method == "tools/list":
            return request.make_json_response(
                self._result_response(
                    payload, {"tools": servers._mcp_tools_list(route)}
                )
            )
        if method == "tools/call":
            params = payload.get("params") or {}
            name = params.get("name")
            if not name:
                return self._error_response(
                    payload, -32602, "Falta el nombre de la herramienta"
                )
            action = servers._mcp_find_tool(route, name)
            if not action:
                return self._error_response(
                    payload, -32602, f"Herramienta no encontrada: {name}"
                )
            return request.make_json_response(
                self._result_response(
                    payload, action._mcp_tool_call(params.get("arguments"))
                )
            )
        return self._error_response(payload, -32601, "Método no encontrado")

    @http.route(
        f"{PROTECTED_RESOURCE_WELL_KNOWN}{MCP_ROOT}/<string:route>",
        type="http",
        auth="none",
        methods=["GET"],
        csrf=False,
    )
    def protected_resource_metadata(self, route, **kwargs):
        return request.make_json_response(mcp_protected_resource_metadata(route))

    @staticmethod
    def _client_protocol_version(payload):
        requested = (payload.get("params") or {}).get("protocolVersion")
        if isinstance(requested, str) and requested:
            return requested
        return MCP_PROTOCOL_VERSION

    @staticmethod
    def _unauthorized(payload, route):
        challenge = []
        if request.httprequest.headers.get("Authorization"):
            challenge.append('error="invalid_token"')
        challenge.append(
            f'resource_metadata="{mcp_protected_resource_metadata_url(route)}"'
        )
        challenge.append(f'scope="{MCP_SCOPE}"')
        return request.make_json_response(
            {
                "jsonrpc": "2.0",
                "id": payload.get("id"),
                "error": {"code": -32000, "message": "No autorizado"},
            },
            headers={
                "WWW-Authenticate": f"Bearer {', '.join(challenge)}",
                "Cache-Control": "no-store",
            },
            status=401,
        )

    @staticmethod
    def _result_response(payload, result):
        return {"jsonrpc": "2.0", "id": payload.get("id"), "result": result}

    @staticmethod
    def _error_response(payload, code, message, status=200):
        return request.make_json_response(
            {
                "jsonrpc": "2.0",
                "id": (payload or {}).get("id"),
                "error": {"code": code, "message": message},
            },
            status=status,
        )
