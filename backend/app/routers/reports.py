from fastapi import APIRouter, Depends, Response
import json
from urllib.parse import quote
from sqlalchemy.orm import Session

from app.database import get_db
from app.services.report_service import (
    _archive_path,
    csv_report,
    json_report,
    list_archives,
    markdown_report,
    read_archive,
)

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("/summary.md")
def summary_markdown(db: Session = Depends(get_db)):
    return Response(markdown_report(db), media_type="text/markdown; charset=utf-8")


@router.get("/summary.json")
def summary_json(db: Session = Depends(get_db)):
    return json_report(db)


@router.get("/summary.csv")
def summary_csv(db: Session = Depends(get_db)):
    return Response(csv_report(db), media_type="text/csv; charset=utf-8")


@router.get("/archives")
def report_archives():
    return {"archives": list_archives()}


@router.get("/archives/{archive_name}")
def report_archive_detail(archive_name: str):
    return read_archive(archive_name)


@router.get("/archives/{archive_name}/download")
def report_archive_download(archive_name: str):
    path = _archive_path(archive_name)
    return Response(json.dumps(read_archive(archive_name), ensure_ascii=False), media_type="application/json",
                    headers={"Content-Disposition": "attachment; filename*=UTF-8''" + quote(path.name)})
