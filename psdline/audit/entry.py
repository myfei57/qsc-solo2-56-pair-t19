"""审计条目。"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..store import GENESIS_DIGEST


@dataclass(frozen=True)
class AuditEntry:
    """一条审计流水。

    ``seq``、``prev_digest`` 和 ``digest`` 是落盘信封上的链信息；内存里刚构造但
    尚未写入的记录使用创世前驱和空摘要。
    """

    id: str
    kind: str
    train_id: str
    station_id: str
    at: float
    detail: dict = field(default_factory=dict)
    seq: int = 0
    prev_digest: str = GENESIS_DIGEST
    digest: str = ""

    def as_record(self) -> dict:
        """返回要参与哈希的业务记录。"""

        return {
            "id": self.id,
            "kind": self.kind,
            "train_id": self.train_id,
            "station_id": self.station_id,
            "at": self.at,
            "detail": dict(self.detail),
        }

    def as_dict(self) -> dict:
        """返回控制台友好的完整视图。"""

        return {
            **self.as_record(),
            "seq": self.seq,
            "prev_digest": self.prev_digest,
            "digest": self.digest,
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "AuditEntry":
        """同时兼容新链信封、完整视图和旧版裸记录。"""

        raw = payload.get("record") if isinstance(payload.get("record"), dict) else payload
        detail = raw.get("detail", {})
        entry = cls(
            id=str(raw.get("id", "")),
            kind=str(raw.get("kind", "")),
            train_id=str(raw.get("train_id", "")),
            station_id=str(raw.get("station_id", "")),
            at=float(raw.get("at", 0.0)),
            detail=dict(detail) if isinstance(detail, dict) else {},
            seq=int(payload.get("seq", 0) or 0),
            prev_digest=str(payload.get("prev_digest", GENESIS_DIGEST) or GENESIS_DIGEST),
            digest=str(payload.get("digest", "") or ""),
        )
        return entry
