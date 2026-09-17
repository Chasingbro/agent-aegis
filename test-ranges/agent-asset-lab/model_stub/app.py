from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Deterministic Model Simulator")
class ChatRequest(BaseModel):
    messages: list[dict] = []
    tools: list[dict] = []

@app.get("/health")
def health():
    return {"status": "ok", "model": "sim-model-v1"}

@app.post("/v1/chat/completions")
def completion(req: ChatRequest):
    return {"id": "sim-fixed", "object": "chat.completion", "choices": [{
        "index": 0, "message": {"role": "assistant", "content": "deterministic response"}, "finish_reason": "stop"}]}
