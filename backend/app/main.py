import json

from fastapi import FastAPI, HTTPException, Request
from pydantic import ValidationError

from backend.app.analysis import analyze_message
from backend.app.schemas import AnalyzeRequest, AnalyzeResponse

MAX_REQUEST_BYTES = 16_384

app = FastAPI(title="PhishShield Web API", version="0.1.0")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/analyze", response_model=AnalyzeResponse, response_model_by_alias=True)
async def analyze(request: Request) -> AnalyzeResponse:
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_REQUEST_BYTES:
                raise HTTPException(status_code=413, detail="Request body exceeds the size limit.")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header.") from exc

    body = await request.body()
    if len(body) > MAX_REQUEST_BYTES:
        raise HTTPException(status_code=413, detail="Request body exceeds the size limit.")

    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Request body must be valid JSON.") from exc

    try:
        payload = AnalyzeRequest.model_validate(data)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail="Request does not match the analysis schema.") from exc

    return analyze_message(payload.message_text)
