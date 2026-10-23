import json
import re

import psycopg2

from odoo import api, fields, models
from odoo.exceptions import ValidationError
from odoo.tools.safe_eval import safe_eval


# Write methods that must be blocked on restricted models/recordsets
_MCP_BLOCKED_WRITE_METHODS = frozenset({
    "create", "write", "unlink", "copy",
    "_create", "_write", "_unlink",
    "flush", "flush_recordset",
    "invalidate_cache", "invalidate_recordset",
    "modified",
})

# Attributes that must be blocked to prevent cursor/registry access
_MCP_BLOCKED_ATTRIBUTES = frozenset({
    "cr", "cursor", "registry", "env",
})


class _McpRestrictedRecordset:
    """Wrapper around a recordset that blocks write operations
    unless the model is the allowed one.
    """

    __slots__ = ("_recordset", "_allowed_model")

    def __init__(self, recordset, allowed_model):
        self._recordset = recordset
        self._allowed_model = allowed_model

    def __getattr__(self, name):
        # Block dangerous attributes
        if name in _MCP_BLOCKED_ATTRIBUTES:
            raise ValidationError(
                "Acceso directo a atributos internos no permitido."
            )
        # Block write methods on non-allowed models
        if name in _MCP_BLOCKED_WRITE_METHODS:
            if self._recordset._name != self._allowed_model:
                def _blocked(*args, **kwargs):
                    raise ValidationError(
                        f"Operación «{name}» no permitida en el modelo «{self._recordset._name}». "
                        f"Solo se permite crear/modificar/borrar en el modelo «{self._allowed_model}» "
                        f"definido en la acción de servidor."
                    )
                return _blocked
        attr = getattr(self._recordset, name)
        # Wrap returned recordsets from search, browse, filtered, etc.
        if callable(attr):
            def _wrapped(*args, **kwargs):
                result = attr(*args, **kwargs)
                if isinstance(result, models.BaseModel):
                    return _McpRestrictedRecordset(result, self._allowed_model)
                if isinstance(result, (list, tuple)):
                    return type(result)(
                        _McpRestrictedRecordset(r, self._allowed_model)
                        if isinstance(r, models.BaseModel) else r
                        for r in result
                    )
                return result
            return _wrapped
        # Wrap recordset attributes
        if isinstance(attr, models.BaseModel):
            return _McpRestrictedRecordset(attr, self._allowed_model)
        return attr

    def __getitem__(self, key):
        result = self._recordset[key]
        if isinstance(result, models.BaseModel):
            return _McpRestrictedRecordset(result, self._allowed_model)
        return result

    def __iter__(self):
        for rec in self._recordset:
            yield _McpRestrictedRecordset(rec, self._allowed_model)

    def __len__(self):
        return len(self._recordset)

    def __bool__(self):
        return bool(self._recordset)

    def __repr__(self):
        return repr(self._recordset)

    def __dir__(self):
        return dir(self._recordset)


class _McpRestrictedModel:
    """Wrapper around an Odoo model that blocks write operations
    unless the model is the allowed one.
    """

    __slots__ = ("_model", "_allowed_model")

    def __init__(self, model, allowed_model):
        self._model = model
        self._allowed_model = allowed_model

    def __getattr__(self, name):
        # Block dangerous attributes
        if name in _MCP_BLOCKED_ATTRIBUTES:
            raise ValidationError(
                "Acceso directo a atributos internos no permitido."
            )
        attr = getattr(self._model, name)
        # Block write methods on non-allowed models
        if name in _MCP_BLOCKED_WRITE_METHODS:
            if self._model._name != self._allowed_model:
                def _blocked(*args, **kwargs):
                    raise ValidationError(
                        f"Operación «{name}» no permitida en el modelo «{self._model._name}». "
                        f"Solo se permite crear/modificar/borrar en el modelo «{self._allowed_model}» "
                        f"definido en la acción de servidor."
                    )
                return _blocked
        # Wrap methods that return recordsets or model classes
        if callable(attr):
            def _wrapped(*args, **kwargs):
                result = attr(*args, **kwargs)
                if isinstance(result, models.BaseModel):
                    return _McpRestrictedRecordset(result, self._allowed_model)
                if isinstance(result, type) and issubclass(result, models.BaseModel):
                    # Model class returned (e.g., from with_context, sudo, with_env)
                    return _McpRestrictedModel(result, allowed_model=self._allowed_model)
                if isinstance(result, (list, tuple)):
                    return type(result)(
                        _McpRestrictedRecordset(r, self._allowed_model)
                        if isinstance(r, models.BaseModel) else r
                        for r in result
                    )
                return result
            return _wrapped
        # Wrap recordset attributes
        if isinstance(attr, models.BaseModel):
            return _McpRestrictedRecordset(attr, self._allowed_model)
        return attr

    def __dir__(self):
        return dir(self._model)


class _McpRestrictedEnv:
    """Wrapper around an Odoo environment that restricts write operations
    to a single allowed model (from ir.actions.server.model_id).

    Read operations (search, read, browse, etc.) are allowed on any model.
    Write operations (create, write, unlink) are only allowed on the allowed model.
    Direct cursor access is blocked to prevent raw SQL.
    """

    __slots__ = ("_env", "_allowed_model")

    def __init__(self, env, allowed_model):
        self._env = env
        self._allowed_model = allowed_model

    def __getattr__(self, name):
        # Block dangerous attributes
        if name in _MCP_BLOCKED_ATTRIBUTES:
            raise ValidationError(
                "Acceso directo a cursor/registro de base de datos no permitido. "
                "Use el ORM de Odoo (env[model].create/write/unlink) para operaciones de datos."
            )
        attr = getattr(self._env, name)
        # Wrap recordsets from env attributes
        if isinstance(attr, models.BaseModel):
            return _McpRestrictedRecordset(attr, self._allowed_model)
        # Wrap callable results (e.g., env.ref())
        if callable(attr):
            def _wrapped(*args, **kwargs):
                result = attr(*args, **kwargs)
                if isinstance(result, models.BaseModel):
                    return _McpRestrictedRecordset(result, self._allowed_model)
                if isinstance(result, type) and issubclass(result, models.BaseModel):
                    # Model class returned (e.g., from with_context, sudo)
                    return _McpRestrictedModel(result, allowed_model=self._allowed_model)
                if isinstance(result, (list, tuple)):
                    return type(result)(
                        _McpRestrictedRecordset(r, self._allowed_model)
                        if isinstance(r, models.BaseModel) else r
                        for r in result
                    )
                return result
            return _wrapped
        return attr

    def __getitem__(self, model_name):
        """Return a restricted model that enforces write restrictions."""
        model = self._env[model_name]
        return _McpRestrictedModel(model, allowed_model=self._allowed_model)

    def __dir__(self):
        return dir(self._env)


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
    mcp_allow_write = fields.Boolean(
        string="Permitir escritura",
        default=False,
        help="Si está activo, el código de esta acción puede crear, modificar y "
             "borrar registros cuando se ejecuta desde MCP. Si está desactivado, "
             "se ejecuta en una transacción de solo lectura y cualquier escritura "
             "se rechaza.",
    )

    mcp_url = fields.Char(
        string="URL MCP",
        compute="_compute_mcp_url",
        help="URL del endpoint MCP generada a partir de la ruta: /mcp/<ruta>.",
    )

    @api.depends("is_mcp", "mcp_route")
    def _compute_mcp_url(self):
        for action in self:
            action.mcp_url = (
                f"/mcp/{action.mcp_route}"
                if action.is_mcp and action.mcp_route
                else False
            )

    @api.constrains("is_mcp", "mcp_route", "state", "code", "mcp_allow_write", "model_id")
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
            if action.mcp_allow_write and not action.model_id:
                raise ValidationError(
                    "Para permitir escritura (mcp_allow_write), debe definirse "
                    "el campo «Modelo» (model_id) en la acción de servidor. "
                    "Solo se podrán crear/modificar/borrar registros de ese modelo."
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

    def _get_eval_context(self, action):
        """Override to provide a restricted environment for MCP actions.

        When mcp_allow_write is True, wraps env to only allow write operations
        on the model specified by model_id. Blocks direct cursor access.
        When mcp_allow_write is False, blocks all write operations and cursor.
        """
        ctx = super()._get_eval_context(action)
        if not self.is_mcp:
            return ctx
        if not self.mcp_allow_write:
            # Write not allowed: block all writes and cursor access
            ctx["env"] = _McpRestrictedEnv(self.env, allowed_model="__none__")
            return ctx
        # Write allowed: restrict writes to model_id.model only
        allowed_model = self.model_id.model if self.model_id else None
        if not allowed_model:
            # No model_id set but write allowed: block all writes for safety
            ctx["env"] = _McpRestrictedEnv(self.env, allowed_model="__none__")
            return ctx
        # Wrap env to restrict writes to allowed_model and block cursor
        ctx["env"] = _McpRestrictedEnv(self.env, allowed_model=allowed_model)
        return ctx

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
        if self.mcp_allow_write:
            return self._mcp_run_code(arguments)
        with self.env.registry.cursor() as cr:
            cr.execute("SET TRANSACTION READ ONLY")
            return self.with_env(self.env(cr=cr))._mcp_run_code(arguments)

    def _mcp_run_code(self, arguments):
        eval_context = self._get_eval_context(self)
        eval_context["args"] = dict(arguments or {})
        try:
            with self.env.cr.savepoint():
                safe_eval(
                    self.code.strip(), eval_context, mode="exec", filename=str(self)
                )
        except psycopg2.errors.ReadOnlySqlTransaction as e:
            if self.mcp_allow_write:
                return self._mcp_error_result(f"{type(e).__name__}: {e}")
            return self._mcp_error_result(
                "Esta acción MCP es de solo lectura: no puede crear, modificar ni "
                "borrar registros. Active «Permitir escritura» en la acción para "
                f"habilitarlo. Detalle: {e}"
            )
        except Exception as e:
            return self._mcp_error_result(f"{type(e).__name__}: {e}")
        if "result" not in eval_context:
            return self._mcp_error_result(
                "El código de la acción no asignó la variable «result»."
            )
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

    @staticmethod
    def _mcp_error_result(message):
        return {
            "content": [{"type": "text", "text": message}],
            "isError": True,
        }
