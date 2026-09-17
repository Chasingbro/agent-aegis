import os
import uuid
from fastapi import FastAPI, Header
from pydantic import BaseModel

app = FastAPI(title="Asset Lab Agent")

class RunRequest(BaseModel):
    prompt: str
    actor: str = "demo-user"

@app.get("/health")
def health():
    return {"status": "ok", "agent": "asset-lab-agent"}

@app.post("/login")
def login(user: str = "demo-user"):
    return {"access_token": "demo-token", "user": user}

@app.post("/run")
def run(req: RunRequest, x_trace_id: str | None = Header(default=None)):
    return {"trace_id": x_trace_id or str(uuid.uuid4()), "instance_id": str(uuid.uuid4()),
            "agent": "asset-lab-agent", "prompt_size": len(req.prompt),
            "model_endpoint": os.environ.get("MODEL_ENDPOINT")}
