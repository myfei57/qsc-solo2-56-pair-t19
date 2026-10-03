"""审计链校验。

校验器只读不改，回答三个问题：

1. 每段是否完整——封存段对照锚点（链式段逐记录重放，遗留段按原始行折叠），
   活动段与链头链态对照；
2. 跨段是否接续——每段重放后的链头必须等于下一段第一条记录的 ``prev``，序号
   必须连续；锚点之间也用 ``prev_anchor_head`` 串了链，锚点被替换也能发现；
3. 从哪一条开始对不上——返回第一个失配条目的位置（段号、段内序号、记录 id）
   与失配原因，而不是只给一个布尔值。

锚点里同时存了段起始链头与起始序号，因此单段校验不需要从头回放；整链校验
始终从创世重放一遍，锚点只作为固定下来的对照点。
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Iterator

from .hash import GENESIS_DIGEST, digest_bytes, digest_record, fold

ANCHOR_SUFFIX = ".anchor.json"
MODE_CHAINED = "chained"
MODE_LEGACY = "legacy"
MODE_EMPTY = "empty"


@dataclass(frozen=True)
class Mismatch:
    """一次失配的位置与原因。"""

    reason: str
    segment: int | None = None
    offset: int | None = None
    seq: int | None = None
    entry_id: str = ""
    expected: str = ""
    actual: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "reason": self.reason,
            "segment": self.segment,
            "offset": self.offset,
            "seq": self.seq,
            "entry_id": self.entry_id,
            "expected": self.expected,
            "actual": self.actual,
        }


@dataclass
class SegmentReport:
    """单个段的校验结果。"""

    segment: int
    sealed: bool
    mode: str  # chained | legacy | empty
    records: int
    head_digest: str
    segment_digest: str
    start_digest: str = GENESIS_DIGEST
    head_seq: int = 0
    first_seq: int | None = None
    last_seq: int | None = None
    segment_digest: str = ""
    ok: bool = True
    mismatch: Mismatch | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "segment": self.segment,
            "sealed": self.sealed,
            "mode": self.mode,
            "records": self.records,
            "first_seq": self.first_seq,
            "last_seq": self.last_seq,
            "start_digest": self.start_digest,
            "head_digest": self.head_digest,
            "head_seq": self.head_seq,
            "segment_digest": self.segment_digest,
            "ok": self.ok,
            "mismatch": self.mismatch.as_dict() if self.mismatch else None,
        }


@dataclass
class ChainReport:
    """整链校验结果。"""

    ok: bool
    segments_checked: int = 0
    records_checked: int = 0
    sealed_segments: int = 0
    legacy_segments: int = 0
    head_digest: str = GENESIS_DIGEST
    head_seq: int = 0
    active_segment: int | None = None
    mismatches: list[Mismatch] = field(default_factory=list)
    segments: list[SegmentReport] = field(default_factory=list)
    algo: str = "sha256"

    @property
    def first_mismatch(self) -> Mismatch | None:
        """返回最早的一处失配（先段锚点，再段内顺序）。"""

        return self.mismatches[0] if self.mismatches else None

    def as_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "algo": self.algo,
            "segments_checked": self.segments_checked,
            "records_checked": self.records_checked,
            "sealed_segments": self.sealed_segments,
            "legacy_segments": self.legacy_segments,
            "active_segment": self.active_segment,
            "head_digest": self.head_digest,
            "head_seq": self.head_seq,
            "first_mismatch": self.first_mismatch.as_dict() if self.first_mismatch else None,
            "mismatches": [item.as_dict() for item in self.mismatches],
            "segments": [item.as_dict() for item in self.segments],
        }


def anchor_path_for(segment_path: str) -> str:
    """由段文件路径推导锚点文件路径。"""

    return segment_path + ANCHOR_SUFFIX


def read_anchor(path: str) -> dict[str, Any] | None:
    """读取锚点；不存在返回 ``None``，损坏抛出 ``ValueError``。"""

    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"锚点损坏: {path}: {error}") from error
    if not isinstance(payload, dict):
        raise ValueError(f"锚点格式非法: {path}")
    return payload


def replay_chained(
    records: list[dict[str, Any]],
    start_digest: str,
    start_seq: int,
    segment: int,
) -> tuple[list[Mismatch], str, int, str, int | None, int | None]:
    """逐记录重放一个链式段。

    返回（失配列表、段末链头、段末序号、段折叠摘要、首序号、末序号）。
    失配后按「期望链」继续重放，避免一处篡改引发雪崩式误报；失配条目本身的
    实际值仍然逐条记录。
    """

    mismatches: list[Mismatch] = []
    head = start_digest
    running = start_digest
    expected_seq = start_seq
    head_seq = start_seq
    first_seq: int | None = None
    last_seq: int | None = None
    for offset, record in enumerate(records):
        expected_seq += 1
        record_id = str(record.get("id", ""))
        actual_seq = int(record.get("seq", 0) or 0)
        actual_prev = str(record.get("prev", "") or "")
        recomputed = digest_record(record)
        actual_digest = str(record.get("digest", "") or "")

        if first_seq is None:
            first_seq = actual_seq
        last_seq = actual_seq
        if actual_seq != expected_seq:
            mismatches.append(
                Mismatch(
                    reason="seq_gap",
                    segment=segment,
                    offset=offset,
                    seq=actual_seq,
                    entry_id=record_id,
                    expected=str(expected_seq),
                )
            )
        if actual_prev != head:
            mismatches.append(
                Mismatch(
                    reason="prev_mismatch",
                    segment=segment,
                    offset=offset,
                    seq=actual_seq,
                    entry_id=record_id,
                    expected=head,
                    actual=actual_prev,
                )
            )
        if actual_digest != recomputed:
            mismatches.append(
                Mismatch(
                    reason="digest_mismatch",
                    segment=segment,
                    offset=offset,
                    seq=actual_seq,
                    entry_id=record_id,
                    expected=recomputed,
                    actual=actual_digest,
                )
            )
        # 期望链：内容以重算摘要为准；序号失配后按实际序号重同步，使缺口只报
        # 一次，定位信息集中在第一处失配。
        running = fold(running, recomputed)
        head = recomputed
        expected_seq = actual_seq
        head_seq = actual_seq
    return (
        mismatches,
        head,
        head_seq,
        running,
        first_seq,
        last_seq,
    )


def fold_legacy(raw_lines: list[bytes], start_digest: str) -> str:
    """按原始行折叠遗留段，返回虚拟链头（同时也是段折叠摘要）。"""

    running = start_digest
    for raw in raw_lines:
        running = fold(running, digest_bytes(raw))
    return running


def iter_raw_lines(path: str) -> Iterator[bytes]:
    """逐行产出段文件的原始 JSON 字节（去掉行尾换行），供遗留段折叠共用。"""

    with open(path, "rb") as handle:
        for raw in handle:
            yield raw.rstrip(b"\r\n")


def _anchor_mismatch(segment: int, field_name: str, expected: object, actual: object) -> Mismatch:
    return Mismatch(
        reason=f"anchor_{field_name}_mismatch",
        segment=segment,
        expected=str(expected),
        actual=str(actual),
    )


def verify_chain(journal: Any, chain_state: dict[str, Any] | None = None) -> ChainReport:
    """从创世开始重放整链并对照全部锚点与链头状态。

    ``journal`` 需要提供 ``segment_paths()`` 与 ``iter_segment_raw(index)``
    （见 :class:`psdline.store.JsonlJournal`）。
    """

    report = ChainReport(ok=True)
    paths = list(journal.segment_paths())
    if not paths:
        if chain_state and chain_state.get("head_digest") not in (None, "", GENESIS_DIGEST):
            report.mismatches.append(
                Mismatch(reason="chain_state_without_segments", expected=GENESIS_DIGEST,
                         actual=str(chain_state.get("head_digest")))
            )
            report.ok = False
        return report

    head = GENESIS_DIGEST
    expected_seq = 0
    prev_anchor_head = GENESIS_DIGEST

    for index, _path in enumerate(paths):
        sealed = index < len(paths) - 1 or read_anchor(anchor_path_for(paths[index])) is not None
        anchor = read_anchor(anchor_path_for(paths[index]))
        raw_lines = [line for line in iter_raw_lines(paths[index]) if line.strip()]
        segment_mismatches: list[Mismatch] = []
        mode = MODE_CHAINED
        report_mismatch: Mismatch | None = None

        anchor_head_for_next = head
        if anchor is not None:
            mode = str(anchor.get("mode", MODE_CHAINED))
            if anchor.get("prev_anchor_head", GENESIS_DIGEST) != prev_anchor_head:
                segment_mismatches.append(
                    _anchor_mismatch(
                        index,
                        "chain",
                        prev_anchor_head,
                        anchor.get("prev_anchor_head", GENESIS_DIGEST),
                    )
                )
            anchor_start = str(anchor.get("start_digest", ""))
            if anchor_start != head:
                segment_mismatches.append(_anchor_mismatch(index, "start", head, anchor_start))
            anchor_start_seq = int(anchor.get("start_seq", -1))
            if anchor_start_seq != expected_seq:
                segment_mismatches.append(
                    _anchor_mismatch(index, "start_seq", expected_seq, anchor_start_seq)
                )
            # 下一段必须接在「锚点固定的链头」之后；锚点本身被改时下一段起点失配
            # 会立刻暴露，同时保留这里的锚点链失配。
            anchor_head_for_next = str(anchor.get("head_digest", head))

        records: list[dict[str, Any]] = []
        corrupt = 0
        for offset, raw in enumerate(raw_lines):
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                corrupt += 1
                segment_mismatches.append(
                    Mismatch(reason="corrupt_line", segment=index, offset=offset)
                )
                continue
            if not isinstance(parsed, dict):
                corrupt += 1
                segment_mismatches.append(
                    Mismatch(reason="corrupt_line", segment=index, offset=offset)
                )
                continue
            records.append(parsed)

        # 无锚点段：模式按段内记录判定。全是无链字段的记录即遗留段（旧版本数据，
        # 通常在启动恢复时已补锚点；走到这里说明恢复被跳过或锚点被删）。
        if anchor is None and records and all(not str(item.get("digest", "")) for item in records):
            mode = MODE_LEGACY

        if mode == MODE_LEGACY:
            segment_digest = fold_legacy(raw_lines, head)
            head_after = segment_digest
            first_seq = last_seq = None
            head_seq = expected_seq
            records_checked = len(raw_lines)
            if not corrupt:
                if anchor is not None and str(anchor.get("segment_digest", "")) != segment_digest:
                    segment_mismatches.append(
                        _anchor_mismatch(index, "digest", segment_digest,
                                        anchor.get("segment_digest", ""))
                    )
                if anchor is not None and str(anchor.get("head_digest", "")) != head_after:
                    segment_mismatches.append(
                        _anchor_mismatch(index, "head", head_after,
                                        anchor.get("head_digest", ""))
                    )
                if anchor is not None and int(anchor.get("records", -1)) != len(raw_lines):
                    segment_mismatches.append(
                        _anchor_mismatch(index, "records", len(raw_lines),
                                        anchor.get("records", -1))
                    )
                if anchor is None and sealed:
                    segment_mismatches.append(Mismatch(reason="anchor_missing", segment=index))
        elif not records and not raw_lines:
            segment_digest = head
            head_after = head
            first_seq = last_seq = None
            head_seq = expected_seq
            records_checked = 0
            if anchor is not None and int(anchor.get("records", -1)) != 0:
                segment_mismatches.append(
                    _anchor_mismatch(index, "records", 0, anchor.get("records", -1))
                )
        else:
            rec_mismatches, head_after, head_seq, segment_digest, first_seq, last_seq = (
                replay_chained(records, head, expected_seq, index)
            )
            segment_mismatches.extend(rec_mismatches)
            records_checked = len(raw_lines)
            if anchor is not None:
                checks = (
                    ("head", str(anchor.get("head_digest", "")), head_after),
                    ("head_seq", int(anchor.get("head_seq", -1)), head_seq),
                    ("digest", str(anchor.get("segment_digest", "")), segment_digest),
                    ("records", int(anchor.get("records", -1)), len(records) + corrupt),
                )
                for field_name, expected, actual in checks:
                    if expected != actual:
                        segment_mismatches.append(
                            _anchor_mismatch(index, field_name, expected, actual)
                        )

        if sealed and anchor is None:
            segment_mismatches.append(Mismatch(reason="anchor_missing", segment=index))

        if segment_mismatches:
            report.ok = False
            report_mismatch = segment_mismatches[0]
            report.mismatches.extend(segment_mismatches)

        segment_report = SegmentReport(
            segment=index,
            sealed=sealed,
            mode=mode if (records or raw_lines) else MODE_EMPTY,
            records=len(raw_lines),
            start_digest=head,
            head_digest=head_after,
            head_seq=head_seq,
            first_seq=first_seq,
            last_seq=last_seq,
            segment_digest=segment_digest,
            ok=not segment_mismatches,
            mismatch=report_mismatch,
        )
        report.segments.append(segment_report)
        report.records_checked += records_checked
        if sealed:
            report.sealed_segments += 1
        if mode == MODE_LEGACY:
            report.legacy_segments += 1

        head = head_after if anchor is None else anchor_head_for_next
        expected_seq = head_seq
        prev_anchor_head = anchor_head_for_next if anchor is not None else prev_anchor_head

    last_index = len(paths) - 1
    report.active_segment = last_index
    report.head_digest = head
    report.head_seq = expected_seq

    if chain_state is not None:
        state_active = int(chain_state.get("active_segment", last_index))
        # 链头状态允许领先一个段（最后一段刚封存、新段文件还没建），落后才算异常。
        if state_active not in (last_index, last_index + 1):
            report.mismatches.append(
                Mismatch(
                    reason="chain_state_segment_mismatch",
                    expected=f"{last_index}|{last_index + 1}",
                    actual=str(state_active),
                )
            )
        if str(chain_state.get("head_digest", "")) != head:
            report.mismatches.append(
                Mismatch(
                    reason="chain_state_head_mismatch",
                    expected=head,
                    actual=str(chain_state.get("head_digest", "")),
                )
            )
        if int(chain_state.get("head_seq", expected_seq)) != expected_seq:
            report.mismatches.append(
                Mismatch(
                    reason="chain_state_seq_mismatch",
                    expected=expected_seq,
                    actual=str(chain_state.get("head_seq")),
                )
            )
        if report.mismatches:
            report.ok = False
    report.segments_checked = len(paths)
    return report


def verify_segment(journal: Any, index: int) -> SegmentReport:
    """只校验一个封存段（直接以它自己的锚点为根，不从创世回放）。"""

    path = journal.segment_path(index)
    anchor = read_anchor(anchor_path_for(path))
    if anchor is None:
        raise ValueError(f"段 {index} 没有锚点，无法按段校验")
    start_digest = str(anchor.get("start_digest", GENESIS_DIGEST))
    start_seq = int(anchor.get("start_seq", 0))
    mode = str(anchor.get("mode", MODE_CHAINED))
    raw_lines = [line for line in iter_raw_lines(path) if line.strip()]

    mismatch: Mismatch | None = None
    if mode == MODE_LEGACY:
        segment_digest = fold_legacy(raw_lines, start_digest)
        head_after = segment_digest
        first_seq = last_seq = None
        head_seq = 0
        if segment_digest != str(anchor.get("segment_digest", "")):
            mismatch = _anchor_mismatch(index, "digest", segment_digest,
                                        anchor.get("segment_digest", ""))
    elif not raw_lines:
        segment_digest = start_digest
        head_after = start_digest
        first_seq = last_seq = None
        head_seq = start_seq
        if int(anchor.get("records", -1)) != 0:
            mismatch = _anchor_mismatch(index, "records", 0, anchor.get("records", -1))
    else:
        records = [json.loads(line) for line in raw_lines]
        rec_mismatches, head_after, _end, segment_digest, first_seq, last_seq = replay_chained(
            records, start_digest, start_seq, index
        )
        head_seq = int(last_seq or start_seq + len(records))
        checks = (
            str(anchor.get("head_digest", "")) != head_after,
            int(anchor.get("head_seq", -1)) != head_seq,
            str(anchor.get("segment_digest", "")) != segment_digest,
            int(anchor.get("records", -1)) != len(records),
        )
        if rec_mismatches:
            mismatch = rec_mismatches[0]
        elif any(checks):
            mismatch = Mismatch(reason="anchor_value_mismatch", segment=index)

    return SegmentReport(
        segment=index,
        sealed=True,
        mode=mode if raw_lines else MODE_EMPTY,
        records=len(raw_lines),
        start_digest=start_digest,
        head_digest=head_after,
        head_seq=head_seq,
        first_seq=first_seq,
        last_seq=last_seq,
        segment_digest=segment_digest,
        ok=mismatch is None,
        mismatch=mismatch,
    )
