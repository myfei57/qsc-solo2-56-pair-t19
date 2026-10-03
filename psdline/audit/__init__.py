"""门控审计。

审计是控制链的最后一环：所有到发、开关门、联锁与探测动作都落一条流水，既能按
动作类型检索，也能按资产重建时间线。流水是一条 SHA-256 哈希链，每条记录携带
前一条记录摘要与全局连续序号，段封存时把段头摘要固定到锚点文件；可按段或整链
校验，并定位从哪一条开始对不上（见 :mod:`psdline.audit.verifier`）。
"""

from __future__ import annotations

from .entry import AuditEntry
from .log import AuditChainBroken, AuditLog
from .query import by_kind, by_train, count_by_kind, kinds
from .summary import count, last, latest_by_kind
from .timeline import build_timeline
from .verifier import ChainReport, Mismatch, SegmentReport

__all__ = [
    "AuditChainBroken",
    "AuditEntry",
    "AuditLog",
    "ChainReport",
    "Mismatch",
    "SegmentReport",
    "build_timeline",
    "by_kind",
    "by_train",
    "count",
    "count_by_kind",
    "kinds",
    "last",
    "latest_by_kind",
]
