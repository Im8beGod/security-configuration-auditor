from fastapi import FastAPI

app = FastAPI(
    title="SIH 26155 Network Security Compliance Auditor",
    version="0.1.0",
)


@app.get("/health")
def health_check():
    return {"status": "healthy"}
