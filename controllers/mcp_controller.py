import json
import re
import secrets

from odoo import http
from odoo.http import request

from ..models.ir_actions_server import MCP_TOKEN_PARAM

MCP_SERVER_INFO = {"name": "odoo-mcp-server-action", "version": "1.0.0"}
MCP_PROTOCOL_VERSION = "2025-03-26"


class McpController(http.Controller):
    @http.route(
        "/mcp/<string:route>", type="http", auth="none", methods=["POST"], csrf=False
    )
    def mcp_endpoint(self, route, **kwargs):
        try:
            payload = json.loads(request.httprequest.data.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            return self._error_response(
                None, -32700, "Error de sintaxis JSON", status=400
            )
        # Notificaciones MCP (p. ej. notifications/initialized): sin «id», sin respuesta
        if "id" not in payload:
            return request.make_response("", status=202)
        if not self._check_token():
            return self._error_response(
                payload, -32000, "No autorizado", status=401
            )
        method = payload.get("method")
        if method == "initialize":
            return request.make_json_response(
                self._result_response(
                    payload,
                    {
                        "protocolVersion": MCP_PROTOCOL_VERSION,
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

    def _check_token(self):
        expected = (
            request.env["ir.config_parameter"].sudo().get_param(MCP_TOKEN_PARAM)
        )
        if not expected:
            return False
        match = re.match(r"Bearer (.+)", request.httprequest.headers.get("Authorization", ""))
        if not match:
            return False
        return secrets.compare_digest(match.group(1).strip(), expected)

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
