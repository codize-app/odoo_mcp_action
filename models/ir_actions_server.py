import json
import re

from odoo import api, fields, models
from odoo.exceptions import ValidationError
from odoo.tools.safe_eval import safe_eval

class IrActionsServer(models.Model):
    _inherit = "ir.actions.server"

    is_mcp = fields.Boolean(
        string="Servidor MCP",
        default=False,
        help="Si está activo, esta acción de servidor se expone como herramienta "
             "MCP en la ruta indicada.",
    )
    mcp_route = fields.Char(
        string="Ruta MCP",
        help="Segmento de URL del endpoint: la acción será visible en "
             "/mcp/<ruta>. Varias acciones pueden compartir la misma ruta "
             "para agruparse en el mismo endpoint.",
    )

    @api.constrains("is_mcp", "mcp_route", "state", "code")
    def _check_mcp_route(self):
        for action in self:
            if not action.is_mcp:
                continue
            if action.state != "code":
                raise ValidationError(
                    "Las acciones MCP deben ser de tipo «Ejecutar código Python»."
                )
            if not action.code or not action.code.strip():
                raise ValidationError(
                    "Las acciones MCP deben tener código Python en el campo «Código»."
                )
            if not action.mcp_route:
                raise ValidationError("Las acciones MCP deben definir una ruta MCP.")
            if not re.fullmatch(r"[a-z][a-z0-9_-]*", action.mcp_route):
                raise ValidationError(
                    "La ruta MCP solo puede contener minúsculas, números, "
                    "guion bajo y guion, y debe empezar por una letra."
                )

    def _mcp_tool_name(self):
        self.ensure_one()
        xml_ids = self.sudo().get_external_id()
        return xml_ids.get(self.id) or f"accion_{self.id}"

    @api.model
    def _mcp_find_tool(self, route, name):
        actions = self.sudo().search(
            [
                ("is_mcp", "=", True),
                ("mcp_route", "=", route),
                ("state", "=", "code"),
            ],
            order="sequence, name, id",
        )
        for action in actions:
            if action._mcp_tool_name() == name:
                return action
        return actions[:0]

    @api.model
    def _mcp_route_exists(self, route):
        return bool(
            self.sudo().search_count(
                [
                    ("is_mcp", "=", True),
                    ("mcp_route", "=", route),
                    ("state", "=", "code"),
                ]
            )
        )

    @api.model
    def _mcp_tools_list(self, route):
        actions = self.sudo().search(
            [
                ("is_mcp", "=", True),
                ("mcp_route", "=", route),
                ("state", "=", "code"),
            ],
            order="sequence, name, id",
        )
        return [
            {
                "name": action._mcp_tool_name(),
                "description": action.name,
                "inputSchema": {"type": "object", "properties": {}},
            }
            for action in actions
        ]

    def _mcp_tool_call(self, arguments):
        self.ensure_one()
        eval_context = self._get_eval_context(self)
        eval_context["args"] = dict(arguments or {})
        try:
            safe_eval(
                self.code.strip(), eval_context, mode="exec", filename=str(self)
            )
        except Exception as e:
            return {
                "content": [
                    {"type": "text", "text": f"{type(e).__name__}: {e}"}
                ],
                "isError": True,
            }
        if "result" not in eval_context:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": "El código de la acción no asignó la variable «result».",
                    }
                ],
                "isError": True,
            }
        result = eval_context["result"]
        if isinstance(result, models.BaseModel):
            result = result.read()
        try:
            text = json.dumps(result, ensure_ascii=False)
            structured = result if isinstance(result, dict) else {"result": result}
        except TypeError:
            text = json.dumps(result, ensure_ascii=False, default=str)
            structured = None
        tool_result = {
            "content": [{"type": "text", "text": text}],
            "isError": False,
        }
        if structured is not None:
            tool_result["structuredContent"] = structured
        return tool_result
