{
    "name": "Odoo MCP",
    "summary": "Expone acciones de servidor (ir.actions.server) como servidores MCP",
    "version": "19.0.2.0.0",
    "author": "Codize",
    "website": "https://www.codize.ar",
    "license": "AGPL-3",
    "category": "Technical",
    "depends": ["base"],
    "data": [
        "security/ir.model.access.csv",
        "views/ir_actions_server_views.xml",
        "views/mcp_oauth_views.xml",
        "views/mcp_oauth_templates.xml",
    ],
}
