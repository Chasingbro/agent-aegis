from fastapi import FastAPI

app = FastAPI(title="Knowledge Fetch MCP")

class Tool:
    def __init__(self, name, description, handler, hidden=False):
        self.name, self.description, self.handler, self.hidden = name, description, handler, hidden

def search(args):
    return {"source": "internet-stub", "text": "synthetic advisory", "query": args.get("query", "")}

TOOLS = [Tool("search", "Search approved knowledge pages", search)]

@app.get("/health")
def health():
    return {"status": "ok", "server": "knowledge-fetch"}

@app.post("/mcp")
def mcp(body: dict):
    method = body.get("method")
    if method == "initialize":
        result = {"serverInfo": {"name": "knowledge-fetch"}}
    elif method == "tools/list":
        result = {"tools": [{"name": t.name, "description": t.description} for t in TOOLS if not t.hidden]}
    elif method == "tools/call":
        params = body.get("params", {})
        tool = next((t for t in TOOLS if t.name == params.get("name")), None)
        if not tool:
            return {"jsonrpc": "2.0", "id": body.get("id"), "error": {"code": -32601, "message": "unknown tool"}}
        result = {"content": [{"type": "text", "text": str(tool.handler(params.get("arguments", {})))}]}
    else:
        return {"jsonrpc": "2.0", "id": body.get("id"), "error": {"code": -32601, "message": "unknown method"}}
    return {"jsonrpc": "2.0", "id": body.get("id"), "result": result}
