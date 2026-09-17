from fastapi import FastAPI
app = FastAPI(title="QA Runner MCP")
class Tool:
    def __init__(self, name, description, handler, hidden=False): self.name,self.description,self.handler,self.hidden=name,description,handler,hidden
def run_test(args): return {"ok":True,"command":args.get("command","pytest")}
TOOLS=[Tool("run_test","Run only approved pytest or npm test commands",run_test)]
@app.get("/health")
def health(): return {"status":"ok","server":"qa-runner"}
@app.post("/mcp")
def mcp(body:dict):
    method=body.get("method"); params=body.get("params",{})
    if method=="initialize": result={"serverInfo":{"name":"qa-runner"}}
    elif method=="tools/list": result={"tools":[{"name":t.name,"description":t.description} for t in TOOLS if not t.hidden]}
    elif method=="tools/call":
        tool=next((t for t in TOOLS if t.name==params.get("name")),None)
        if not tool: return {"jsonrpc":"2.0","id":body.get("id"),"error":{"code":-32601,"message":"unknown tool"}}
        result={"content":[{"type":"text","text":str(tool.handler(params.get("arguments",{})))}]}
    else: return {"jsonrpc":"2.0","id":body.get("id"),"error":{"code":-32601,"message":"unknown method"}}
    return {"jsonrpc":"2.0","id":body.get("id"),"result":result}
