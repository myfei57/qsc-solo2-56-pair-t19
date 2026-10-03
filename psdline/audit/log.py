"""审计流水写入与校验。"""

from __future__ import annotations

import json

from ..clock import Clock
from ..errors import RailError
from ..eventbus import Event, EventBus
from ..ids import IdFactory
from ..store import ChainedJsonlJournal
from .entry import AuditEntry


class AuditLog:
    """哈希链审计流水：内存索引 + 可归档、可校验的分段 JSONL。"""

    def __init__(self, clock: Clock, bus: EventBus, journal: ChainedJsonlJournal) -> None:
        self._clock = clock
        self._bus = bus
        self._journal = journal
        self._ids = IdFactory("audit")
        self._index: list[AuditEntry] = []
        self._bootstrap()

    @property
    def journal(self) -> ChainedJsonlJournal:
        return self._journal

    @property
    def ids(self) -> IdFactory:
        return self._ids

    def _bootstrap(self) -> None:
        """恢复历史索引；链已损坏时保留可确认记录并阻断后续写入。"""

        self._index = [
            AuditEntry.from_dict(item)
            for item in self._journal.recovered_records()
            if isinstance(item, dict)
        ]

    def record(
        self,
        kind: str,
        train_id: str,
        station_id: str,
        at: float | None = None,
        **detail: object,
    ) -> AuditEntry:
        """写入一条带前一条摘要的审计流水。"""

        if not kind:
            raise RailError("审计动作类型为空", component="audit")
        pending = AuditEntry(
            id=self._ids.next(),
            kind=kind,
            train_id=train_id,
            station_id=station_id,
            at=self._clock.now() if at is None else at,
            detail={key: value for key, value in detail.items() if value is not None},
        )
        envelope = self._journal.append(pending.as_record())
        entry = AuditEntry.from_dict(envelope)
        self._index.append(entry)
        self._bus.publish(
            Event.of(
                "audit",
                "audit",
                kind,
                severity="notice",
                train_id=train_id,
                station_id=station_id,
            )
        )
        return entry

    def list(self) -> list[AuditEntry]:
        """返回已恢复的全部历史审计条目与本次进程新增条目。"""

        return list(self._index)

    def replay(self, limit: int = 100_000) -> list[AuditEntry]:
        """从落盘流水回放审计条目，保留链摘要。"""

        records = self._journal.read_all_raw()[:limit]
        return [AuditEntry.from_dict(item) for item in records if isinstance(item, dict)]

    def segments(self) -> list[list[dict]]:
        """按段返回落盘业务记录，供巡检逐段核对。"""

        return [
            self._journal.read_segment(index)
            for index, _path in enumerate(self._journal.segments())
        ]

    def verify_segment(self, segment: int) -> dict:
        """校验指定归档段或活动段。"""

        return self._journal.verify_segment(segment).as_dict()

    def verify(self) -> dict:
        """校验全链，返回每段结果并定位第一条不匹配记录。"""

        return self._journal.verify_report()

    def integrity(self) -> dict:
        """返回当前链健康状态与崩溃恢复信息。"""

        return self._journal.integrity_summary()

    def summary(self) -> dict:
        """返回审计用量、动作分布与链健康概览。"""

        entries = self.list()
        integrity = self.integrity()
        return {
            "entries": len(entries),
            "journal_records": self._journal.count(),
            "segment": self._journal.active_segment(),
            "segments": len(self._journal.segments()),
            "sealed_segments": self._journal.sealed_segment_count(),
            "archive_policy": "record_count",
            "sealed_immutable": True,
            "segment_limit": self._journal.segment_limit,
            "chain_healthy": integrity["healthy"],
            "quarantined_parts": integrity["quarantined_parts"],
            "issue": integrity["issue"],
            "recovery": integrity["recovery"],
            "segment_sizes": [len(items) for items in self.segments()],
            "by_kind": count_kinds(entries),
        }

    def dump(self) -> str:
        """把内存索引序列化成一行 JSON，供状态接口内嵌。"""

        return json.dumps([entry.as_dict() for entry in self.list()], ensure_ascii=False)


def count_kinds(entries: list[AuditEntry]) -> dict[str, int]:
    """按动作类型统计条数。"""

    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry.kind] = counts.get(entry.kind, 0) + 1
    return counts
