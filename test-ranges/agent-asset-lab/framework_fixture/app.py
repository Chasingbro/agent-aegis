from fastapi import FastAPI
app = FastAPI(title="Flow Engine Fixture")
FLOW = {"name": "support-flow", "nodes": ["ChatInput", "Agent", "ToolRouter", "ChatOutput"], "model_base": "http://model-sim:8000/v1"}
@app.get("/health")
def health(): return {"status": "ok", "framework": "flow-engine", "version": "0.9.0"}
@app.get("/api/flows")
def flows(): return {"flows": [FLOW]}
