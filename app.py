from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from pqc_agent import analyze_pdf


BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
REPORT_DIR = BASE_DIR / "reports"

UPLOAD_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)

app = FastAPI(title="PQC Migration Assessment Engine")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")


latest_reports: dict[str, Path] = {}


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="Please upload a PDF file.")

    safe_name = Path(file.filename).name
    if not safe_name.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF uploads are supported.")

    contents = await file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")

    if not contents.startswith(b"%PDF"):
        raise HTTPException(status_code=400, detail="The uploaded file does not appear to be a valid PDF.")

    upload_path = UPLOAD_DIR / f"{uuid4().hex}_{safe_name}"
    upload_path.write_bytes(contents)

    try:
        result = analyze_pdf(upload_path, REPORT_DIR, document_name=safe_name)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except OSError as exc:
        raise HTTPException(status_code=422, detail="The PDF could not be read. Please upload a valid, unencrypted PDF.") from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Analysis failed. Please try another PDF or check the server logs.") from exc

    report_paths = result.pop("report_paths")
    latest_reports.clear()
    latest_reports.update({kind: Path(path) for kind, path in report_paths.items()})

    result["download_links"] = {
        "json": "/download/json",
        "markdown": "/download/markdown",
        "html": "/download/html",
    }
    return result


def _download_report(kind: str, media_type: str) -> FileResponse:
    path = latest_reports.get(kind)
    if not path or not path.exists():
        raise HTTPException(status_code=404, detail="No report is available yet. Run an analysis first.")
    return FileResponse(path, media_type=media_type, filename=path.name)


@app.get("/download/json")
async def download_json():
    return _download_report("json", "application/json")


@app.get("/download/markdown")
async def download_markdown():
    return _download_report("markdown", "text/markdown")


@app.get("/download/html")
async def download_html():
    return _download_report("html", "text/html")
