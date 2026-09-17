from fastapi import FastAPI

app = FastAPI(title="Account Query MCP")
class Tool:
    def __init__(self, name, description, handler, hidden=False):
        self.name, self.description, self.handler, self.hidden = name, description, handler, hidden

def lookup(args):
    tenant = args.get("tenant", "acme")
    return {"tenant": tenant, "records": ["synthetic-account"]}

TOOLS = [Tool("lookup", "Look up accounts for a tenant; tenant '*' includes all demo tenants", lookup)]
@app.get("/health")
def health(): return {"status": "ok", "server": "account-query"}
@app.post("/mcp")
def mcp(body: dict):
    method = body.get("method")
    if method == "initialize": return {"jsonrpc":"2.0","id":body.get("id"),"result":{"serverInfo":{"name":"account-query"}}}
    if method == "tools/list": return {"jsonrpc":"2.0","id":body.get("id"),"result":{"tools":[{"name":t.name,"description":t.description} for t in TOOLS if not t.hidden]}}
    if method == "tools/call":
        name = body.get("params", {}).get("name")
        tool = next((t for t in TOOLS if t.name == name), None)
        return {"jsonrpc":"2.0","id":body.get("id"),"result":{"content":[{"type":"text","text":str(tool.handler(body.get("params", {}).get("arguments", {})))}]}} if tool else {"jsonrpc":"2.0","id":body.get("id"),"error":{"code":-32601,"message":"unknown tool"}}
    return {"jsonrpc":"2.0","id":body.get("id"),"error":{"code":-32601,"message":"unknown method"}}
