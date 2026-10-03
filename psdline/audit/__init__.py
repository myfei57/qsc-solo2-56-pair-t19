"""门控审计。

审计是控制链的最后一环：所有到发、开关门、联锁与探测动作都落一条哈希链流水，
既能按动作类型检索，也能按资产重建时间线。流水按条数分段追加，满段生成归档摘要；
历史记录不改写，事后可按段校验并定位第一条不匹配记录。
"""

from __future__ import annotations

from .entry import AuditEntry
from .log import AuditLog
from .query import by_kind, by_train, count_by_kind, kinds
from .summary import count, last, latest_by_kind
from .timeline import build_timeline

__all__ = [
    "AuditEntry",
    "AuditLog",
    "build_timeline",
    "by_kind",
    "by_train",
    "count",
    "count_by_kind",
    "kinds",
    "last",
    "latest_by_kind",
]
