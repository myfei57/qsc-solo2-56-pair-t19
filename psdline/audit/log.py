"""审计流水写入：可校验的哈希链。

每条记录携带前一条记录的摘要（``prev``）与自身摘要（``digest``），全局连续
``seq``；段封存时把段头摘要、段折叠摘要与前一锚点摘要写进锚点文件固定下来。
启动恢复负责：

* 截掉活动段末尾掉电留下的半行（封存段一个字节都不动）；
* 把链功能上线前写入的遗留数据补成 ``legacy`` 锚点——不重写历史文件，遗留段
  只能提供段级校验粒度，之后第一条链式记录接在遗留虚拟链头上；
* 重放全部段重建链头与序号，并记录发现的断链位置。

断链默认 **只标记不阻断**（fail-open）：审计不能阻断联锁控制，但断链状态会在
状态快照、控制台页面与命令行全部显式暴露；配置 ``fail_closed`` 后断链将拒绝
继续写入。
"""

from __future__ import annotations

import json
import threading
from dataclasses import replace
from typing import Any

from ..clock import Clock
from ..errors import RailError
from ..eventbus import Event, EventBus
from ..ids import IdFactory
from ..store import JsonlJournal
from ..store.jsonfile import JsonStore
from .entry import AuditEntry
from .hash import DIGEST_ALGO, GENESIS_DIGEST, digest_record, fold
from .verifier import (
    Mismatch,
    fold_legacy,
    verify_chain,
    verify_segment,
)

CHAIN_STATE_DOC = "audit/chain"
RECENT_LIMIT = 2_000
#: 链头状态文档的落盘步长：每条记录都做原子替换会把审计吞吐砍半，而链头总能在
#: 启动时从链文件重放恢复；因此每写 N 条（以及封存、断链时）才固定一次。
STATE_FLUSH_EVERY = 64


class AuditChainBroken(RailError):
    """链已断裂且处于 fail-closed 模式，拒绝继续写入。"""


class AuditLog:
    """审计流水：哈希链索引 + 分段 JSONL 落盘 + 定期封存锚点。"""

    def __init__(
        self,
        clock: Clock,
        bus: EventBus,
        journal: JsonlJournal,
        store: JsonStore | None = None,
        fail_closed: bool = False,
    ) -> None:
        self._clock = clock
        self._bus = bus
        self._journal = journal
        self._store = store
        self._fail_closed = bool(fail_closed)
        self._ids = IdFactory("audit")
        self._index: list[AuditEntry] = []
        # 链头内存态的串行锁：控制台是多线程 HTTP 服务，两条审计不能同时推进链。
        # 底层 journal 另有自己的锁保护文件。
        self._lock = threading.RLock()

        self._head_digest = GENESIS_DIGEST
        self._head_seq = 0
        self._running = GENESIS_DIGEST
        self._active_records = 0
        self._active_segment = journal.active_segment()
        self._prev_anchor_head = GENESIS_DIGEST
        self._sealed_legacy = 0
        self._mismatches: list[Mismatch] = []
        self._recovered_dropped_bytes = 0
        self._state_dirty = False
        self._recover()

    # ---- 属性 ---------------------------------------------------------

    @property
    def journal(self) -> JsonlJournal:
        return self._journal

    @property
    def ids(self) -> IdFactory:
        return self._ids

    @property
    def fail_closed(self) -> bool:
        return self._fail_closed

    @property
    def head_digest(self) -> str:
        return self._head_digest

    @property
    def head_seq(self) -> int:
        return self._head_seq

    @property
    def sealed_segments(self) -> int:
        return sum(1 for index in self._journal.segment_indices() if self._journal.anchor_exists(index))

    @property
    def legacy_segments(self) -> int:
        return self._sealed_legacy

    @property
    def broken(self) -> bool:
        return bool(self._mismatches)

    # ---- 写入 ---------------------------------------------------------

    def record(
        self,
        kind: str,
        train_id: str,
        station_id: str,
        at: float | None = None,
        **detail: object,
    ) -> AuditEntry:
        """写入一条审计流水，并把它挂到链尾。"""

        with self._lock:
            return self._record_locked(kind, train_id, station_id, at, detail)

    def _record_locked(
        self,
        kind: str,
        train_id: str,
        station_id: str,
        at: float | None,
        detail: dict[str, object],
    ) -> AuditEntry:
        if not kind:
            raise RailError("审计动作类型为空", component="audit")
        if self._fail_closed and self._mismatches:
            first = self._mismatches[0]
            raise AuditChainBroken(
                f"审计链在段 {first.segment} 偏移 {first.offset} 处断裂"
                f"（{first.reason}），fail-closed 模式拒绝继续写入",
                component="audit",
            )

        target = self._journal.next_writable_segment(self._active_segment)
        if target != self._active_segment:
            # 目标段是没写锚点的满段（旧版本遗留）：先按起点补锚点固定，新记录再
            # 接到该锚点固定的段头之后。
            self._anchor_recovered_full_segment(target - 1)
            anchor = self._journal.read_anchor(target - 1) or {}
            self._head_digest = str(anchor.get("head_digest", self._head_digest))
            self._head_seq = int(anchor.get("head_seq", self._head_seq))
            self._running = self._head_digest
            self._prev_anchor_head = self._head_digest
            self._active_segment = target
            self._active_records = 0

        seq = self._head_seq + 1
        entry = AuditEntry(
            id=self._ids.next(),
            kind=kind,
            train_id=train_id,
            station_id=station_id,
            at=self._clock.now() if at is None else at,
            detail={key: value for key, value in detail.items() if value is not None},
            seq=seq,
            prev=self._head_digest,
        )
        payload = entry.as_dict()
        payload["digest"] = digest_record(payload)
        entry = replace(entry, digest=payload["digest"])
        try:
            self._journal.append_to(target, payload)
        except RailError:
            raise
        self._head_digest = entry.digest
        self._running = fold(self._running, entry.digest)
        self._head_seq = seq
        self._active_records += 1
        self._index.append(entry)
        # 链头状态文档按步长落盘；链文件本身已 fsync，崩溃后能重放恢复。
        self._state_dirty = True
        if self._head_seq % STATE_FLUSH_EVERY == 0:
            self._save_state()
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
        if self._active_records >= self._journal.segment_limit:
            self.archive()
        return entry

    def archive(self) -> dict[str, Any]:
        """手动封存当前活动段（即使没写满），返回封存结果。

        空段不会产生锚点，只推进活动段号；段满时 ``record`` 已自动调用本方法。
        """

        with self._lock:
            return self._archive_locked()

    def _archive_locked(self) -> dict[str, Any]:
        if self._active_records == 0 and not self._journal.anchor_exists(self._active_segment):
            if self._journal.has_segment(self._active_segment):
                # 段文件存在但为空（极端情况下手动归档触发）：推进段号。
                sealed = self._journal.seal_active()
            else:
                sealed = self._active_segment
            self._active_segment = self._journal.active_segment()
            self._save_state(force=True)
            return {"sealed": sealed, "records": 0, "rolled": self._journal.has_segment(sealed)}

        sealed_index = self._active_segment
        head_before = self._running_before_segment(sealed_index)
        head_seq_before = self._head_seq - self._active_records
        anchor = {
            "version": 1,
            "topic": self._journal.topic,
            "segment": sealed_index,
            "mode": "chained",
            "algo": DIGEST_ALGO,
            "records": self._active_records,
            "start_digest": head_before,
            "start_seq": head_seq_before,
            "head_digest": self._head_digest,
            "head_seq": self._head_seq,
            "segment_digest": self._running,
            "prev_anchor_head": self._prev_anchor_head,
        }
        self._verify_then_anchor(sealed_index, anchor)
        self._journal.seal_active()
        self._prev_anchor_head = self._head_digest
        self._active_segment = self._journal.active_segment()
        self._active_records = 0
        self._running = self._head_digest
        self._save_state(force=True)
        return {
            "sealed": sealed_index,
            "records": anchor["records"],
            "head_digest": anchor["head_digest"],
            "segment_digest": anchor["segment_digest"],
            "rolled": True,
        }

    # ---- 读取 ---------------------------------------------------------

    def list(self) -> list[AuditEntry]:
        """返回内存里保留的审计条目。"""

        with self._lock:
            return list(self._index)

    def replay(self, limit: int = 100_000) -> list[AuditEntry]:
        """从落盘流水回放审计条目。"""

        with self._lock:
            records = self._journal.read_all()[:limit]
            return [AuditEntry.from_dict(item) for item in records if isinstance(item, dict)]

    def segments(self) -> list[list[dict]]:
        """按段返回落盘流水，供巡检逐段核对。"""

        with self._lock:
            return [
                self._journal.read_segment(index)
                for index in self._journal.segment_indices()
            ]

    def chain_status(self) -> dict[str, Any]:
        """返回链头与断链状态（状态快照内嵌，不触发全盘扫描）。"""

        with self._lock:
            first = self._mismatches[0] if self._mismatches else None
            return {
                "algo": DIGEST_ALGO,
                "active_segment": self._active_segment,
                "head_seq": self._head_seq,
                "head_digest": self._head_digest,
                "sealed_segments": self.sealed_segments,
                "legacy_segments": self._sealed_legacy,
                "fail_closed": self._fail_closed,
                "broken": bool(self._mismatches),
                "mismatch_count": len(self._mismatches),
                "first_mismatch": first.as_dict() if first else None,
                "recovered_dropped_bytes": self._recovered_dropped_bytes,
            }

    def verify(self) -> dict[str, Any]:
        """从创世重放整链并对照全部锚点与当前链头状态。"""

        with self._lock:
            report = verify_chain(self._journal, self._state_payload())
            return report.as_dict()

    def verify_segment(self, index: int) -> dict[str, Any]:
        """只校验一个已封存段（直接以它的锚点为根）。"""

        with self._lock:
            return verify_segment(self._journal, index).as_dict()

    def summary(self) -> dict:
        """返回审计用量、动作分布与链状态。"""

        with self._lock:
            entries = list(self._index)
            return {
                "entries": len(entries),
                "journal_records": self._journal.count(),
                "segment": self._active_segment,
                "segments": len(self._journal.segment_indices()),
                "segment_sizes": self._journal.segment_sizes(),
                "by_kind": count_kinds(entries),
                "chain": self.chain_status(),
            }

    def dump(self) -> str:
        """把内存索引序列化成一行 JSON，供状态接口内嵌。"""

        with self._lock:
            return json.dumps([entry.as_dict() for entry in self._index], ensure_ascii=False)

    # ---- 恢复 ---------------------------------------------------------

    def _recover(self) -> None:
        indices = list(self._journal.segment_indices())
        if not indices:
            self._save_state(force=True)
            return

        head = GENESIS_DIGEST
        running = GENESIS_DIGEST
        expected_seq = 0
        prev_anchor_head = GENESIS_DIGEST
        legacy_count = 0
        last_index = indices[-1]
        last_segment_anchored = False
        chain_started = False

        for index in indices:
            if index < last_index:
                sealed = True
            else:
                # 活动段：先截半行，再按「满段 / 有锚点」判定它其实已封存。
                self._recovered_dropped_bytes = self._journal.recover_tail(index)
                sealed = self._journal.is_sealed(index)
            head, running, expected_seq, prev_anchor_head, legacy, chain_started = (
                self._recover_segment(
                    index,
                    head,
                    running,
                    expected_seq,
                    prev_anchor_head,
                    sealed=sealed,
                    chain_started=chain_started,
                )
            )
            legacy_count += legacy
            if index == last_index:
                last_segment_anchored = self._journal.anchor_exists(index)

        self._head_digest = head
        self._running = running
        self._head_seq = expected_seq
        self._prev_anchor_head = prev_anchor_head
        self._sealed_legacy = legacy_count
        self._journal.refresh_active()
        if last_segment_anchored:
            # 最后一段已封存（归档过、或旧版本留下的满段/遗留开放段）：链头从
            # 下一段起步。
            self._active_segment = last_index + 1
            self._active_records = 0
            self._running = head
            self._index = []
        else:
            self._active_segment = last_index
            self._active_records = self._journal.segment_sizes()[-1]
            recent = self._journal.read_segment(last_index)
            self._index = [AuditEntry.from_dict(item) for item in recent if isinstance(item, dict)][
                -RECENT_LIMIT:
            ]
        if self._mismatches:
            self._bus.publish(
                Event.of(
                    "audit",
                    "audit",
                    "chain_broken_detected",
                    severity="alarm",
                    reason=self._mismatches[0].reason,
                )
            )
        self._save_state(force=True)

    def _anchor_recovered_full_segment(self, index: int) -> None:
        """写入时发现满段没锚点（旧版本遗留）：按磁盘重放补一个固定点。

        该段在链头状态里已经被重放过（链头本来就在它之后），所以从它前一个锚点
        取起点，再走一遍段重放，复用封存段缺锚点的补锚点逻辑。
        """

        if index < 0 or self._journal.anchor_exists(index):
            return
        prev_anchor = self._journal.read_anchor(index - 1)
        if index == 0 or prev_anchor is not None:
            start_head = GENESIS_DIGEST if index == 0 else str(prev_anchor["head_digest"])
            start_seq = 0 if index == 0 else int(prev_anchor.get("head_seq", 0))
            start_prev = GENESIS_DIGEST if index == 0 else str(
                prev_anchor.get("head_digest", GENESIS_DIGEST)
            )
        else:
            start_head, start_seq, start_prev = GENESIS_DIGEST, 0, GENESIS_DIGEST
        # 段 0 可能是纯遗留（链尚未开始）；有前锚点时链必然已经开始。
        chain_started = index > 0
        self._recover_segment(
            index, start_head, start_head, start_seq, start_prev,
            sealed=True, chain_started=chain_started,
        )
        # _recover_segment 可能记录失配；写入路径要把这些失配同步进链状态。
        self._save_state(force=True)

    def _recover_segment(
        self,
        index: int,
        head: str,
        running: str,
        expected_seq: int,
        prev_anchor_head: str,
        sealed: bool,
        chain_started: bool = False,
    ) -> tuple[str, str, int, str, int, bool]:
        """重放一个段并在需要时补锚点。

        返回（新链头、段运行摘要、新序号、下一锚点链头、遗留标记、本段之后链是否
        已开始）。``chain_started`` 表示此前是否已经出现过链式段：纯无链段只有在
        链尚未开始时才算「遗留数据」，链开始之后再出现无链记录即伪造/损坏。
        """

        path = self._journal.segment_path(index)
        anchor = self._journal.read_anchor(index)
        raw_lines = [line for line in self._journal.iter_segment_raw(index) if line.strip()]

        if anchor is not None:
            mode = str(anchor.get("mode", "chained"))
            if anchor.get("prev_anchor_head", GENESIS_DIGEST) != prev_anchor_head:
                self._mismatches.append(
                    Mismatch(reason="anchor_chain_mismatch", segment=index,
                             expected=prev_anchor_head,
                             actual=str(anchor.get("prev_anchor_head", GENESIS_DIGEST)))
                )
            if mode == "legacy":
                segment_digest = fold_legacy(raw_lines, head)
                if segment_digest != str(anchor.get("segment_digest", "")):
                    self._mismatches.append(
                        Mismatch(reason="anchor_digest_mismatch", segment=index,
                                 expected=segment_digest,
                                 actual=str(anchor.get("segment_digest", "")))
                    )
                if str(anchor.get("head_digest", "")) != segment_digest:
                    self._mismatches.append(
                        Mismatch(reason="anchor_head_mismatch", segment=index,
                                 expected=segment_digest,
                                 actual=str(anchor.get("head_digest", "")))
                    )
                return segment_digest, segment_digest, expected_seq, segment_digest, 1, chain_started
            chained = [self._parse_line(index, offset, line) for offset, line in enumerate(raw_lines)]
            chained = [item for item in chained if item is not None]
            mismatches, seg_head, seg_seq, seg_run, _f, _l = self._replay(
                chained, head, expected_seq, index
            )
            self._mismatches.extend(mismatches)
            if str(anchor.get("head_digest", "")) != seg_head:
                self._mismatches.append(
                    Mismatch(reason="anchor_head_mismatch", segment=index, expected=seg_head,
                             actual=str(anchor.get("head_digest", "")))
                )
            if str(anchor.get("segment_digest", "")) != seg_run:
                self._mismatches.append(
                    Mismatch(reason="anchor_digest_mismatch", segment=index, expected=seg_run,
                             actual=str(anchor.get("segment_digest", "")))
                )
            if int(anchor.get("head_seq", -1)) != seg_seq:
                self._mismatches.append(
                    Mismatch(reason="anchor_seq_mismatch", segment=index, expected=str(seg_seq),
                             actual=str(anchor.get("head_seq", -1)))
                )
            return seg_head, seg_run, seg_seq, seg_head, 0, True

        # 没有锚点。纯无链段只有在链尚未开始时才算遗留数据；链开始之后出现的无链
        # 记录一律按损坏/伪造处理（开放段也不例外，链功能上线后写的记录必有链字段）。
        parsed: list[dict[str, Any]] = []
        for raw in raw_lines:
            item = self._parse_line(index, len(parsed), raw)
            if item is not None:
                parsed.append(item)
        chained = [item for item in parsed if str(item.get("digest", ""))]
        unchained = [item for item in parsed if not str(item.get("digest", ""))]
        pure_legacy = bool(parsed) and not chained and not chain_started

        def write_anchor(mode: str, records: int, seg_head: str, seg_seq: int,
                         seg_run: str, start_head: str, start_seq: int,
                         prev_head: str, extra: dict[str, Any]) -> None:
            self._write_recovered_anchor(
                index,
                {
                    "version": 1,
                    "topic": self._journal.topic,
                    "segment": index,
                    "mode": mode,
                    "algo": DIGEST_ALGO,
                    "records": records,
                    "start_digest": start_head,
                    "start_seq": start_seq,
                    "head_digest": seg_head,
                    "head_seq": seg_seq,
                    "segment_digest": seg_run,
                    "prev_anchor_head": prev_head,
                    **extra,
                },
            )

        if unchained and not pure_legacy:
            # 链已开始后出现无链记录（伪造、截断重放或迁移窗口崩溃留下的混合段）：
            # 逐条标记，不把它们并入链。
            for item in unchained:
                self._mismatches.append(
                    Mismatch(
                        reason="record_without_chain",
                        segment=index,
                        entry_id=str(item.get("id", "")),
                    )
                )

        if pure_legacy:
            # 纯遗留段（含升级时没写满的开放段）：补 legacy 锚点并把它视为封存，
            # 绝不重写段文件。恢复期不调用 journal 滚段，活动段号由 _recover 末尾
            # 按末段是否有锚点统一决定。
            segment_digest = fold_legacy(raw_lines, head)
            write_anchor(
                "legacy", len(parsed), segment_digest, expected_seq,
                segment_digest, head, expected_seq, prev_anchor_head,
                {"migrated": True},
            )
            return segment_digest, segment_digest, expected_seq, segment_digest, 1, False

        mismatches, seg_head, seg_seq, seg_run, _f, _l = self._replay(
            chained, head, expected_seq, index
        )
        self._mismatches.extend(mismatches)
        if sealed and chained:
            # 封存段缺锚点（旧版本留下的满段）：按段内容重放并补固定点。
            write_anchor(
                "chained", len(chained), seg_head, seg_seq, seg_run,
                head, expected_seq, prev_anchor_head, {"recovered": True},
            )
            return seg_head, seg_run, seg_seq, seg_head, 0, True
        return seg_head, seg_run, seg_seq, prev_anchor_head, 0, True

    def _parse_line(self, index: int, offset: int, raw: bytes) -> dict[str, Any] | None:
        try:
            item = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._mismatches.append(Mismatch(reason="corrupt_line", segment=index, offset=offset))
            return None
        if not isinstance(item, dict):
            self._mismatches.append(Mismatch(reason="corrupt_line", segment=index, offset=offset))
            return None
        return item

    def _replay(
        self,
        records: list[dict[str, Any]],
        start_digest: str,
        start_seq: int,
        index: int,
    ):
        # 延迟导入避免与 verifier 形成模块级环。
        from .verifier import replay_chained

        mismatches, seg_head, seg_seq, seg_run, first_seq, last_seq = replay_chained(
            records, start_digest, start_seq, index
        )
        return mismatches, seg_head, seg_seq, seg_run, first_seq, last_seq

    def _write_recovered_anchor(self, index: int, payload: dict[str, Any]) -> None:
        if self._journal.anchor_exists(index):
            return
        try:
            self._journal.write_anchor(index, payload)
        except RailError as error:
            self._mismatches.append(
                Mismatch(reason=f"anchor_write_failed:{error.message}", segment=index)
            )

    # ---- 封存辅助 -----------------------------------------------------

    def _running_before_segment(self, index: int) -> str:
        """求段起点链头：优先读锚点，否则用当前链头不可得时以状态文档为准。"""

        anchor = self._journal.read_anchor(index - 1) if index > 0 else None
        if anchor is not None:
            return str(anchor.get("head_digest", GENESIS_DIGEST))
        if index == 0:
            return GENESIS_DIGEST
        # 理论上前一段一定有锚点（只有活动段没有），兜底从创世重算。
        report = verify_chain(self._journal)
        for item in report.segments:
            if item.segment == index - 1:
                return item.head_digest
        return GENESIS_DIGEST

    def _verify_then_anchor(self, index: int, anchor: dict[str, Any]) -> None:
        """写锚点前对照磁盘重放一次，防止内存链头与落盘不一致。"""

        records = self._journal.read_segment(index)
        start_digest = anchor["start_digest"]
        start_seq = int(anchor["start_seq"])
        from .verifier import replay_chained

        mismatches, seg_head, seg_seq, seg_run, _f, _l = replay_chained(
            records, start_digest, start_seq, index
        )
        if mismatches:
            self._mismatches.extend(mismatches)
            self._bus.publish(
                Event.of(
                    "audit",
                    "audit",
                    "chain_broken_detected",
                    severity="alarm",
                    reason=mismatches[0].reason,
                )
            )
            if self._fail_closed:
                raise AuditChainBroken(
                    f"封存段 {index} 校验失败：{mismatches[0].reason}", component="audit"
                )
        anchor["head_digest"] = seg_head
        anchor["head_seq"] = seg_seq
        anchor["segment_digest"] = seg_run
        self._journal.write_anchor(index, anchor)

    # ---- 链头状态文档 -------------------------------------------------

    def _state_payload(self) -> dict[str, Any]:
        first = self._mismatches[0] if self._mismatches else None
        return {
            "version": 1,
            "algo": DIGEST_ALGO,
            "active_segment": self._active_segment,
            "head_digest": self._head_digest,
            "head_seq": self._head_seq,
            "segment_digest": self._running,
            "prev_anchor_head": self._prev_anchor_head,
            "legacy_segments": self._sealed_legacy,
            "broken": bool(self._mismatches),
            "first_mismatch": first.as_dict() if first else None,
            "recovered_dropped_bytes": self._recovered_dropped_bytes,
        }

    def flush(self) -> None:
        """把链头状态立即落盘（停运、巡检前调用）。"""

        with self._lock:
            self._save_state(force=True)

    def _save_state(self, force: bool = False) -> None:
        if self._store is None:
            return
        if not force and not self._state_dirty and self._head_seq % STATE_FLUSH_EVERY != 0:
            return
        try:
            self._store.write(CHAIN_STATE_DOC, self._state_payload())
            self._state_dirty = False
        except RailError as error:
            # 链头状态写不进不能丢业务，但必须显式暴露。
            self._mismatches.append(Mismatch(reason=f"state_persist_failed:{error.message}"))

def count_kinds(entries: list[AuditEntry]) -> dict[str, int]:
    """按动作类型统计条数。"""

    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry.kind] = counts.get(entry.kind, 0) + 1
    return counts
