from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from src.main import AgentOptions, PQCMigrationAgent, SUPPORTED_EXTENSIONS, markdown_summary


BASE_DIR = Path(__file__).resolve().parent
WEB_DIR = BASE_DIR / "web"
STATIC_DIR = WEB_DIR / "static"
# Vercel Functions reject request bodies above 4.5 MB. Keep this below that
# limit so users get a clear application error instead of a platform failure.
MAX_UPLOAD_BYTES = 4 * 1024 * 1024


app = FastAPI(
    title="PQC Migration Agent",
    version="1.0.0",
    description="Analyze PDF, DOCX, and TXT documents for vulnerable cryptography and PQC migration work.",
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def landing_page() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "pqc-migration-agent"}


@app.post("/analyze")
async def analyze_document(file: UploadFile = File(...)) -> JSONResponse:
    original_name = Path(file.filename or "").name
    extension = Path(original_name).suffix.lower()
    if extension not in SUPPORTED_EXTENSIONS:
        supported = ", ".join(sorted(SUPPORTED_EXTENSIONS))
        raise HTTPException(status_code=400, detail=f"Unsupported file type. Upload one of: {supported}")

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    if len(content) > MAX_UPLOAD_BYTES:
        limit_mb = MAX_UPLOAD_BYTES // (1024 * 1024)
        raise HTTPException(
            status_code=413,
            detail=f"File is too large for the hosted analyzer. Maximum upload size is {limit_mb} MB.",
        )

    with tempfile.TemporaryDirectory(prefix="pqc-agent-") as temp_dir:
        temp_path = Path(temp_dir) / original_name
        temp_path.write_bytes(content)

        agent = PQCMigrationAgent(
            AgentOptions(
                context_chars=120,
                recursive=False,
                include_clean_documents=True,
            )
        )
        report = agent.run(temp_path)
        if report["processing"]["documents_failed"]:
            document = report["documents"][0] if report["documents"] else {}
            detail = document.get("error", "The document could not be parsed.")
            raise HTTPException(status_code=422, detail=detail)

        markdown = markdown_summary(report)
        return JSONResponse(
            {
                "report": report,
                "markdown": markdown,
            }
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=False)
