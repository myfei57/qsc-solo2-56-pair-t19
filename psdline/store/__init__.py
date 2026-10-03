"""文件型持久化。

``JsonStore`` 保存"当前态"文档（每个文档一个 JSON 文件，写时先落临时文件再
原子替换）；``JsonlJournal`` 保存"流水"（按分段追加，只追加不重写）；
``ChainedJsonlJournal`` 保存带哈希链和段归档摘要的审计流水，``StoreMetrics``
给出目录用量，``CommandLog`` 保存门控指令队列。它们都落在
控制服务配置的 ``storage_root`` 下。
"""

from __future__ import annotations

from .chained_journal import (
    CHAIN_VERSION,
    GENESIS_DIGEST,
    ChainedJsonlJournal,
    ChainIssue,
    SegmentCheck,
    digest_payload,
    record_digest,
)
from .commands import CommandLog, DoorCommand
from .jsonfile import JsonStore
from .journal import JsonlJournal
from .metrics import StoreMetrics

__all__ = [
    "CHAIN_VERSION",
    "GENESIS_DIGEST",
    "ChainedJsonlJournal",
    "ChainIssue",
    "CommandLog",
    "DoorCommand",
    "JsonStore",
    "JsonlJournal",
    "SegmentCheck",
    "StoreMetrics",
    "digest_payload",
    "record_digest",
]
