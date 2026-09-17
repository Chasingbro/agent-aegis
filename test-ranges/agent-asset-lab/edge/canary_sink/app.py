from fastapi import FastAPI
app = FastAPI(title="Local Canary Sink")
RECEIPTS = []
@app.get("/health")
def health(): return {"status": "ok", "receipts": len(RECEIPTS)}
@app.post("/collect")
def collect(body: dict):
    RECEIPTS.append(body)
    return {"accepted": True, "count": len(RECEIPTS)}
@app.get("/receipts")
def receipts(): return {"receipts": RECEIPTS}
