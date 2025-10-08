from fastapi import FastAPI


app = FastAPI(title="Pentest Lab Backend", version="0.1")

@app.get("/")
def root():
    return {"status": "ok", "message": "Pentest Lab Backend API"}