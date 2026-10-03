"""审计链摘要原语。

链上每条记录的摘要是对「去掉 digest 字段后的记录本体」做规范化 JSON 序列化后
取 SHA-256；规范化参数固定（键排序、无空白、不转义非 ASCII），保证不同进程、
不同 Python 版本算出同一个值。段摘要用同样长度的摘要反复折叠：

    running_0 = GENESIS_DIGEST
    running_i = SHA256(running_{i-1} || record_digest_i)

遗留段（迁移前写入、没有逐记录链）改用原始行字节折叠，只能提供段级校验粒度。
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

#: 创世摘要：64 个十六进制 0，表示链的起点。
GENESIS_DIGEST = "0" * 64

#: 摘要算法名，写进锚点便于将来轮换。
DIGEST_ALGO = "sha256"


def canonical_payload(record: dict[str, Any]) -> bytes:
    """返回一条记录用于摘要的规范化字节串（不含 digest 字段本身）。"""

    body = {key: value for key, value in record.items() if key != "digest"}
    return json.dumps(
        body, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str
    ).encode("utf-8")


def digest_record(record: dict[str, Any]) -> str:
    """计算一条记录的摘要。"""

    return hashlib.sha256(canonical_payload(record)).hexdigest()


def digest_bytes(raw: bytes) -> str:
    """计算任意字节串的摘要（遗留段按原始行使用）。"""

    return hashlib.sha256(raw).hexdigest()


def fold(running: str, next_digest: str) -> str:
    """把一条摘要折叠进段运行摘要。"""

    return hashlib.sha256(bytes.fromhex(running) + bytes.fromhex(next_digest)).hexdigest()


def short(digest: str, length: int = 12) -> str:
    """返回摘要的短展示形式。"""

    return digest[:length] if digest else ""
