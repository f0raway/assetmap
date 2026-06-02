from __future__ import annotations

from pathlib import Path

from sqlmodel import Session, SQLModel, create_engine


def _sqlite_path_from_url(url: str) -> Path | None:
    prefix = "sqlite:///"
    if url.startswith(prefix):
        return Path(url[len(prefix) :])
    return None


def create_db_and_engine(database_url: str):
    sqlite_path = _sqlite_path_from_url(database_url)
    if sqlite_path is not None:
        sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(database_url, connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    return engine


def get_session(engine) -> Session:
    return Session(engine)
