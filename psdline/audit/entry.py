"""审计条目。

除业务字段外，每条记录携带链字段：``seq`` 是从 1 起的全局连续序号，``prev`` 是
前一条记录（规范化后）的摘要，``digest`` 是本条记录（不含 digest 字段本身）的
摘要。迁移前的遗留数据没有链字段，反序列化时 seq 置 0、摘要留空，由迁移逻辑
补段级锚点。
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class AuditEntry:
    """一条审计流水。"""

    id: str
    kind: str
    train_id: str
    station_id: str
    at: float
    detail: dict = field(default_factory=dict)
    seq: int = 0
    prev: str = ""
    digest: str = ""

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "train_id": self.train_id,
            "station_id": self.station_id,
            "at": self.at,
            "detail": dict(self.detail),
            "seq": self.seq,
            "prev": self.prev,
            "digest": self.digest,
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "AuditEntry":
        detail = payload.get("detail", {})
        try:
            seq = int(payload.get("seq", 0) or 0)
        except (TypeError, ValueError):
            seq = 0
        return cls(
            id=str(payload.get("id", "")),
            kind=str(payload.get("kind", "")),
            train_id=str(payload.get("train_id", "")),
            station_id=str(payload.get("station_id", "")),
            at=float(payload.get("at", 0.0)),
            detail=dict(detail) if isinstance(detail, dict) else {},
            seq=seq,
            prev=str(payload.get("prev", "") or ""),
            digest=str(payload.get("digest", "") or ""),
        )
