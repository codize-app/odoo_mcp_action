# Odoo MCP - Server Actiones

## Funcionalidad

Expone acciones de servidor nativas (`ir.actions.server`) como **herramientas MCP** (Model Context Protocol) vía JSON-RPC 2.0 sobre HTTP POST. Cada acción MCP ejecuta su propio campo `code` (Python) y devuelve el resultado al LLM.

Cada **ruta MCP** (`mcp_route`) es un endpoint segmentado: `/mcp/<ruta>` lista y llama solo las acciones MCP que compartan esa ruta. Varias rutas = varias áreas segmentadas.

## Requisitos

- Odoo 19 Community.
- Módulo instalado (depende solo de `base`).

## Crear un MCP

1. Ajustes Técnicos → Acciones de servidor → Nueva.
2. Tipo: **Ejecutar código Python**; elegir modelo (opcional, para `record`/`records`).
3. Pestaña **MCP**: activar **¿Es endpoint MCP?** y poner una **ruta** (p. ej. `ventas`).

El código debe asignar la respuesta a la variable `result` (serializable a JSON; un recordset se convierte con `read()`). Disponibles las variables nativas (`env`, `model`, `record`, `records`, `log`, `time`, `datetime`, …) más `args` (dict de argumentos que envía el LLM).

Ejemplo (modelos de `base`, sin dependencias extra):

```python
result = env["res.partner"].search_read(
    [("is_company", "=", True)], ["name", "email"], limit=args.get("limite", 10)
)
```

## Autenticación

Crear el parámetro del sistema `mcp_server_action.token` (Ajustes Técnicos → Parámetros del sistema) con un valor secreto. El cliente envía el header:

```
Authorization: Bearer <token>
```

Si el parámetro no existe o no coincide, el endpoint responde **401** en todo (seguro por defecto).

## Conectar un cliente

URL del endpoint: `https://<odoo>/mcp/<ruta>` (p. ej. `https://mi-odoo.example.com/mcp/ventas`).

El nombre de cada herramienta es el xml_id de la acción si tiene uno (`tools/list` lo devuelve); para acciones creadas desde la interfaz es `accion_<id>`.

Ejemplo con `curl`:

```bash
URL=https://mi-odoo.example.com/mcp/ventas
TOKEN=mi-secreto

# initialize
curl -sS -X POST "$URL" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'

# tools/list
curl -sS -X POST "$URL" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'

# tools/call
curl -sS -X POST "$URL" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"accion_5","arguments":{"limite":5}}}'
```

Compatibilidad: clientes MCP que soporten HTTP simple con Bearer (n8n, agentes custom). Claude Desktop (OAuth) queda fuera de alcance.

## Seguridad

- El código de la acción se ejecuta como **superuser**; el acceso al endpoint lo habilita el token.
- Solo administradores crean acciones (campo `code` restringido a sistema) y parámetros del sistema.
- Cada ruta segmenta qué ve cada cliente: un cliente de `/mcp/ventas` no ve ni llama herramientas de otra ruta.
