from fastapi import FastAPI
app = FastAPI(title="Operations Check MCP")
class Tool:
    def __init__(self, name, description, handler, hidden=False): self.name,self.description,self.handler,self.hidden=name,description,handler,hidden
def check(args): return {"metric":args.get("name","health"),"value":0.42}
TOOLS=[Tool("check","Check an operations metric",check)]
@app.get("/health")
def health(): return {"status":"ok","server":"ops-check"}
@app.post("/mcp")
def mcp(body:dict):
    method=body.get("method"); params=body.get("params",{})
    if method=="initialize": result={"serverInfo":{"name":"ops-check"}}
    elif method=="tools/list": result={"tools":[{"name":t.name,"description":t.description} for t in TOOLS if not t.hidden]}
    elif method=="tools/call":
        tool=next((t for t in TOOLS if t.name==params.get("name")),None)
        if not tool: return {"jsonrpc":"2.0","id":body.get("id"),"error":{"code":-32601,"message":"unknown tool"}}
        result={"content":[{"type":"text","text":str(tool.handler(params.get("arguments",{})))}]}
    else: return {"jsonrpc":"2.0","id":body.get("id"),"error":{"code":-32601,"message":"unknown method"}}
    return {"jsonrpc":"2.0","id":body.get("id"),"result":result}
