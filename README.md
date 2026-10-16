# Odoo MCP - Server Actiones

## Funcionalidad

Creador de Servidores MCP para Odoo nativo. Expone acciones de servidor nativas (`ir.actions.server`) como **herramientas MCP** (Model Context Protocol) vía JSON-RPC 2.0 sobre HTTP POST. Cada acción MCP ejecuta su propio campo `code` (Python) y devuelve el resultado al LLM.

Cada **ruta MCP** (`mcp_route`) es un endpoint segmentado: `/mcp/<ruta>` lista y llama solo las acciones MCP que compartan esa ruta. Varias rutas = varias áreas segmentadas.

## Requisitos

- Odoo 19 Community.
- Módulo instalado (depende solo de `base`).

## Crear un MCP

1. Ajustes Técnicos → Acciones de servidor → Nueva.
2. Tipo: **Ejecutar código Python**; elegir modelo (opcional, para `record`/`records`).
3. Pestaña **MCP**: activar **¿Es endpoint MCP?** y poner una **ruta** (p. ej. `sales`).

El código debe asignar la respuesta a la variable `result` (serializable a JSON; un recordset se convierte con `read()`). Disponibles las variables nativas (`env`, `model`, `record`, `records`, `log`, `time`, `datetime`, …) más `args` (dict de argumentos que envía el LLM).

Ejemplo (modelos de `base`, sin dependencias extra):

```python
result = env["res.partner"].search_read(
    [("is_company", "=", True)], ["name", "email"]
)
```

## Autenticación (OAuth 2.1, sin configurar nada en el cliente)

Los endpoints están protegidos con **OAuth 2.1** y el módulo hace también de servidor de autorización, así que no hay ningún secreto que copiar en el cliente:

- Sin token, el endpoint responde **401** con
  `WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource/mcp/<ruta>"`, `scope="mcp"`.
  Ese 401 es lo que dispara el inicio de sesión en los clientes MCP.
- El cliente lee el **documento de recurso protegido** (RFC 9728), que apunta al servidor de autorización (este Odoo), y luego sus **metadatos** (RFC 8414).
- El cliente se identifica de una de estas dos formas:
  - **Client ID Metadata Document (CIMD)**: su `client_id` es una URL HTTPS pública que publica él mismo (Claude usa `https://claude.ai/oauth/mcp-oauth-client-metadata`, Claude Code `https://claude.ai/oauth/claude-code-client-metadata`). Odoo descarga ese documento, comprueba que su `client_id` coincide con la URL y valida la `redirect_uri` contra las `redirect_uris` declaradas.
  - **Registro dinámico** (RFC 7591), para clientes que no publican documento.
- El usuario inicia sesión **en su Odoo** y autoriza en una pantalla que muestra el host del `client_id`, la URL de retorno y los permisos.
- El token se emite con **PKCE obligatorio (S256)** y queda ligado al endpoint concreto (`resource`, RFC 8707): un token de `/mcp/sales` no sirve en `/mcp/purchases`.

### Conectar Claude

Ajustes → **Conectores** → *Añadir conector personalizado* → URL `https://<odoo>/mcp/<ruta>` (p. ej. `https://mi-odoo.example.com/mcp/ventas`). Claude abre la pantalla de Odoo, el usuario autoriza y la conexión queda lista. No hay nada que configurar en Claude: sin pegatinas de token y sin claves propias.

### Conectar Claude Code

```bash
claude mcp add --transport http ventas https://mi-odoo.example.com/mcp/ventas
claude mcp list
```

Claude Code declara `http://localhost/callback` y `http://127.0.0.1/callback`, así que las redirecciones de bucle local se comparan **ignorando el puerto** (RFC 8252 §7.3).

### Clientes propios (n8n, agentes, curl)

Pueden usar el flujo OAuth estándar (`/mcp/oauth/authorize` + `/mcp/oauth/token`) o el registro dinámico. Comprobación rápida de que el endpoint está vivo:

```bash
curl -si https://mi-odoo.example.com/mcp/ventas \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
# 401 + WWW-Authenticate: Bearer resource_metadata="…", scope="mcp"

curl -sS https://mi-odoo.example.com/mcp/ventas \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
```

El nombre de cada herramienta es el xml_id de la acción si tiene uno (`tools/list` lo devuelve); para acciones creadas desde la interfaz es `accion_<id>`.

### Endpoints publicados

| Ruta | Qué es |
| - | - |
| `/mcp/<ruta>` | Endpoint MCP (JSON-RPC 2.0, requiere token) |
| `/.well-known/oauth-protected-resource/mcp/<ruta>` | Documento RFC 9728 del endpoint |
| `/.well-known/oauth-authorization-server` | Metadatos RFC 8414 del servidor de autorización |
| `/mcp/oauth/authorize` | Autorización (PKCE S256, pantalla de consentimiento) |
| `/mcp/oauth/token` | Token y refresco (rotación) |
| `/mcp/oauth/register` | Registro dinámico de clientes (RFC 7591) |

Solo se publica el documento de recurso protegido con la ruta sufijada (`…/mcp/<ruta>`); la variante raíz `/.well-known/oauth-protected-resource` no se sirve porque cada endpoint es un recurso distinto y el 401 siempre incluye el puntero exacto.

### Parámetros del sistema (opcionales)

| Parámetro | Por defecto | Para qué |
| - | - | - |
| `mcp_server_action.auth_group` | `base.group_system` | Grupo cuyos usuarios pueden autorizar clientes MCP (admite xml_id o id) |
| `mcp_server_action.public_base_url` | URL de la petición | URL pública base, si Odoo está detrás de un proxy que no propaga esquema/host |

El parámetro antiguo `mcp_server_action.token` **ya no se usa**: si venía de la versión con token fijo, bórrelo.

### Revocar y caducar

- Los tokens de acceso duran **1 hora**; los de refresco, **30 días**, y **rotan en cada uso** (reutilizar uno rotado revoca toda la familia).
- Para cortar un acceso: Ajustes Técnicos → **MCP (OAuth) → Tokens MCP** y borrar sus filas (efecto inmediato), o borrar el cliente en **Clientes MCP** para impedir nuevas autorizaciones.

## Seguridad

- El código de la acción se ejecuta como **superusuario**; el acceso lo habilita OAuth, y solo los usuarios del grupo configurado (por defecto Ajustes/Administración) pueden autorizar.
- Cada token vale solo para la ruta MCP a la que se emitió (audiencia RFC 8707); no se aceptan tokens de otro público.
- Códigos, tokens y secretos se guardan **hasheados** (SHA-256); los códigos de autorización son de un solo uso y caducan en 5 minutos.
- El documento CIMD se descarga solo desde URLs **HTTPS públicas**, sin redirecciones, con tamaño (16 KB) y caché acotados, y se rechaza si no es JSON válido, si su `client_id` no coincide con la URL, si pide autenticación con secreto o si alguna `redirect_uri` no comparte el origen (salvo bucle local). Esto también corta los intentos de SSRF hacia direcciones internas.
- La pantalla de consentimiento muestra el host del `client_id` (lo único que el cliente no puede falsificar), la URL de retorno completa y un aviso extra cuando solo hay retornos de bucle local.
- El registro dinámico está limitado a 1000 clientes para acotar el abuso.
- Solo administradores crean acciones (campo `code` restringido a sistema) y parámetros del sistema.
- Cada ruta segmenta qué ve cada cliente: un cliente de `/mcp/sales` no ve ni llama herramientas de otra ruta.
