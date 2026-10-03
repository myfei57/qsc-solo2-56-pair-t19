"""审计哈希链：写入、封存、校验、定位、迁移与崩溃恢复。"""

from __future__ import annotations

import json
import os

import pytest

from psdline.audit import AuditChainBroken, AuditLog
from psdline.audit.hash import GENESIS_DIGEST, digest_record, fold
from psdline.clock import ManualClock
from psdline.eventbus import EventBus
from psdline.store import JsonStore, JsonlJournal


def _log(tmp_path, segment_limit=3, fail_closed=False):
    root = str(tmp_path)
    store = JsonStore(root)
    return AuditLog(
        ManualClock(),
        EventBus(),
        JsonlJournal(root, "audit", segment_limit=segment_limit),
        store=store,
        fail_closed=fail_closed,
    )


def _relog(log, tmp_path, segment_limit=3, fail_closed=False):
    """用同一目录重新构造一个审计日志（模拟进程重启）。"""

    root = str(tmp_path)
    return AuditLog(
        ManualClock(),
        EventBus(),
        JsonlJournal(root, "audit", segment_limit=segment_limit),
        store=JsonStore(root),
        fail_closed=fail_closed,
    )


def _open_log(tmp_path, segment_limit=3, fail_closed=False):
    return _relog(None, tmp_path, segment_limit, fail_closed)


def test_records_carry_chain_fields(tmp_path):
    log = _log(tmp_path)
    first = log.record("arrive", "T1", "ST1")
    second = log.record("depart", "T1", "ST1")
    assert first.seq == 1 and first.prev == GENESIS_DIGEST
    assert len(first.digest) == 64
    assert second.seq == 2 and second.prev == first.digest
    # digest 覆盖除 digest 外的全部字段，改任何字段都会变。
    payload = first.as_dict()
    payload["train_id"] = "T9"
    assert digest_record(payload) != first.digest


def test_auto_archive_fixes_anchor_on_roll(tmp_path):
    log = _log(tmp_path, segment_limit=3)
    for kind in ("a", "b", "c", "d"):
        log.record(kind, "T", "S")
    status = log.chain_status()
    assert status["broken"] is False
    assert status["sealed_segments"] == 1
    anchor = log.journal.read_anchor(0)
    assert anchor["mode"] == "chained"
    assert anchor["records"] == 3
    assert anchor["head_seq"] == 3
    report = log.verify()
    assert report["ok"] is True
    assert [item["mode"] for item in report["segments"]] == ["chained", "chained"]


def test_manual_archive_empty_active_segment(tmp_path):
    log = _log(tmp_path, segment_limit=3)
    for kind in ("a", "b", "c"):
        log.record(kind, "T", "S")  # 自动封存段 0
    result = log.archive()  # 活动段 1 为空
    assert result["records"] == 0
    entry = log.record("d", "T", "S")
    assert entry.seq == 4
    assert log.verify()["ok"] is True
    assert _relog(log, tmp_path).verify()["ok"] is True


def test_manual_archive_non_full_segment(tmp_path):
    log = _log(tmp_path, segment_limit=10)
    log.record("a", "T", "S")
    log.record("b", "T", "S")
    result = log.archive()
    assert result["records"] == 2 and result["rolled"] is True
    assert log.journal.anchor_exists(0)
    next_entry = log.record("c", "T", "S")
    assert next_entry.seq == 3 and next_entry.prev != GENESIS_DIGEST
    assert log.verify()["ok"] is True


def test_verify_single_sealed_segment(tmp_path):
    log = _log(tmp_path, segment_limit=2)
    for kind in ("a", "b", "c"):
        log.record(kind, "T", "S")
    report = log.verify_segment(0)
    assert report["ok"] is True
    assert report["sealed"] is True
    assert report["records"] == 2 and report["head_seq"] == 2
    with pytest.raises(ValueError):
        log.verify_segment(99)


def test_tampered_record_is_localized(tmp_path):
    log = _log(tmp_path, segment_limit=3)
    for kind in ("a", "b", "c", "d"):
        log.record(kind, "T", "S")
    path = log.journal.segment_path(0)
    lines = open(path, encoding="utf-8").read().splitlines()
    record = json.loads(lines[1])
    record["train_id"] = "HACKED"
    lines[1] = json.dumps(record, ensure_ascii=False)
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")

    reopened = _relog(log, tmp_path)
    report = reopened.verify()
    assert report["ok"] is False
    first = report["first_mismatch"]
    assert first["reason"] == "digest_mismatch"
    assert first["segment"] == 0
    assert first["offset"] == 1
    assert reopened.broken is True
    # 封存段文件没有被动过。
    assert reopened.journal.read_segment(0)[1]["train_id"] == "HACKED"


def test_deleted_record_is_localized_by_seq_gap(tmp_path):
    log = _log(tmp_path, segment_limit=3)
    for kind in ("a", "b", "c", "d"):
        log.record(kind, "T", "S")
    path = log.journal.segment_path(0)
    lines = open(path, encoding="utf-8").read().splitlines()
    del lines[1]
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    first = _relog(log, tmp_path).verify()["first_mismatch"]
    assert first["reason"] == "seq_gap"
    assert first["offset"] == 1


def test_tampered_anchor_is_detected(tmp_path):
    log = _log(tmp_path, segment_limit=2)
    for kind in ("a", "b", "c", "d"):
        log.record(kind, "T", "S")
    anchor_path = log.journal.segment_path(0) + ".anchor.json"
    anchor = json.load(open(anchor_path, encoding="utf-8"))
    anchor["head_digest"] = "f" * 64
    json.dump(anchor, open(anchor_path, "w", encoding="utf-8"))
    report = _relog(log, tmp_path).verify()
    assert report["ok"] is False
    reasons = {item["reason"] for item in report["mismatches"]}
    assert "anchor_head_mismatch" in reasons


def test_anchor_is_write_once(tmp_path):
    log = _log(tmp_path, segment_limit=2)
    for kind in ("a", "b", "c"):
        log.record(kind, "T", "S")
    with pytest.raises(Exception):
        log.journal.write_anchor(0, {"forged": True})


def test_fail_open_keeps_writing_after_break(tmp_path):
    log = _log(tmp_path, segment_limit=3)
    for kind in ("a", "b", "c", "d"):
        log.record(kind, "T", "S")
    path = log.journal.segment_path(0)
    lines = open(path, encoding="utf-8").read().splitlines()
    record = json.loads(lines[0])
    record["kind"] = "x"
    lines[0] = json.dumps(record, ensure_ascii=False)
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    reopened = _relog(log, tmp_path)
    assert reopened.broken is True
    after = reopened.record("after", "T", "S")  # 不阻断
    assert after.seq == 5


def test_fail_closed_blocks_writes_after_break(tmp_path):
    log = _log(tmp_path, segment_limit=3, fail_closed=True)
    for kind in ("a", "b", "c"):
        log.record(kind, "T", "S")
    # 活动段里塞一条没有链字段的伪造记录。
    with open(log.journal.segment_path(1), "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"id": "fake", "kind": "x"}) + "\n")
    reopened = _relog(log, tmp_path, fail_closed=True)
    assert reopened.broken is True
    with pytest.raises(AuditChainBroken):
        reopened.record("z", "T", "S")


def test_crash_half_line_is_truncated(tmp_path):
    log = _log(tmp_path, segment_limit=3)
    for kind in ("a", "b", "c", "d"):
        log.record(kind, "T", "S")
    path = log.journal.segment_path(1)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write('{"id": "partial", "kin')  # 无换行的半行
    reopened = _relog(log, tmp_path)
    assert reopened.chain_status()["recovered_dropped_bytes"] > 0
    assert reopened.verify()["ok"] is True
    assert reopened.head_seq == 4
    reopened.record("e", "T", "S")
    assert reopened.verify()["ok"] is True


def test_legacy_open_segment_is_migrated(tmp_path):
    # 旧版本写的无链记录，最后一段没写满（最常见的升级现场）。
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    for index in range(3):
        journal.append(
            {"id": f"old-{index}", "kind": "k", "train_id": "T", "station_id": "S",
             "at": 1.0 + index, "detail": {}}
        )
    log = _open_log(tmp_path, segment_limit=2)
    assert log.legacy_segments == 2
    report = log.verify()
    assert report["ok"] is True
    assert [item["mode"] for item in report["segments"]] == ["legacy", "legacy"]
    entry = log.record("new", "T", "S")
    assert entry.seq == 1
    assert entry.prev != GENESIS_DIGEST  # 接在遗留虚拟链头之后
    assert log.verify()["ok"] is True
    assert _relog(log, tmp_path, segment_limit=2).verify()["ok"] is True


def test_legacy_full_tail_is_migrated(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    for index in range(4):
        journal.append(
            {"id": f"old-{index}", "kind": "k", "train_id": "T", "station_id": "S",
             "at": 1.0 + index, "detail": {}}
        )
    log = _open_log(tmp_path, segment_limit=2)
    assert log.verify()["ok"] is True
    assert log.summary()["segment"] == 2  # 满的遗留末段已封存，新写入从段 2 起
    entry = log.record("new", "T", "S")
    assert entry.seq == 1
    assert log.verify()["ok"] is True


def test_legacy_segment_tamper_is_detected(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    for index in range(3):
        journal.append(
            {"id": f"old-{index}", "kind": "k", "train_id": "T", "station_id": "S",
             "at": 1.0 + index, "detail": {}}
        )
    log = _open_log(tmp_path, segment_limit=2)
    assert log.verify()["ok"] is True
    path = log.journal.segment_path(0)
    lines = open(path, encoding="utf-8").read().splitlines()
    record = json.loads(lines[0])
    record["kind"] = "HACK"
    lines[0] = json.dumps(record, ensure_ascii=False)
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    report = _relog(log, tmp_path, segment_limit=2).verify()
    assert report["ok"] is False
    assert report["first_mismatch"]["segment"] == 0


def test_forged_unchained_record_after_chain_started(tmp_path):
    log = _log(tmp_path, segment_limit=3)
    for kind in ("a", "b", "c"):
        log.record(kind, "T", "S")
    with open(log.journal.segment_path(1), "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"id": "fake", "kind": "x"}) + "\n")
    reopened = _relog(log, tmp_path)
    assert reopened.broken is True
    assert reopened.chain_status()["first_mismatch"]["reason"] == "record_without_chain"


def test_chain_state_flush_and_restart(tmp_path):
    log = _log(tmp_path, segment_limit=512)
    for index in range(70):
        log.record("k", "T", "S", index=index)
    state_path = os.path.join(str(tmp_path), "audit", "chain.json")
    persisted = json.load(open(state_path, encoding="utf-8"))
    assert persisted["head_seq"] == 64  # 每 64 条固定一次
    log.flush()
    persisted = json.load(open(state_path, encoding="utf-8"))
    assert persisted["head_seq"] == 70
    assert _relog(log, tmp_path, segment_limit=512).head_seq == 70


def test_segment_digest_is_ordered_fold(tmp_path):
    # 段折叠摘要对顺序敏感：交换两条记录的行序必然变化。
    log = _log(tmp_path, segment_limit=3)
    for kind in ("a", "b", "c"):
        log.record(kind, "T", "S")
    anchor = log.journal.read_anchor(0)
    path = log.journal.segment_path(0)
    lines = open(path, encoding="utf-8").read().splitlines()
    swapped = [lines[1], lines[0], lines[2]]
    open(path, "w", encoding="utf-8").write("\n".join(swapped) + "\n")
    report = _relog(log, tmp_path).verify_segment(0)
    assert report["ok"] is False
    assert anchor["segment_digest"]
