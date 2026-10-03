"""审计流水与文件型持久化。"""

from __future__ import annotations

import json

from psdline.audit import (
    AuditLog,
    build_timeline,
    by_kind,
    by_train,
    count,
    count_by_kind,
    kinds,
    last,
    latest_by_kind,
)
from psdline.clock import ManualClock
from psdline.eventbus import Event, EventBus
from psdline.errors import StorageError
from psdline.store import (
    ChainedJsonlJournal,
    CommandLog,
    DoorCommand,
    JsonStore,
    JsonlJournal,
    StoreMetrics,
)


def _log(tmp_path) -> tuple[AuditLog, EventBus, ManualClock]:
    store = JsonStore(str(tmp_path))
    bus = EventBus()
    clock = ManualClock()
    return AuditLog(clock, bus, ChainedJsonlJournal(store.root, "audit", segment_limit=2)), bus, clock


def test_audit_records_and_replays(tmp_path):
    log, bus, _clock = _log(tmp_path)
    seen: list[Event] = []
    log.record("arrive", "T01", "ST1")
    log.record("depart", "T02", "ST1")
    unsubscribe = bus.subscribe("audit", seen.append)
    log.record("gap_probe", "T01", "ST1", clear=True)
    unsubscribe()
    entries = log.list()
    assert count(entries) == 3
    assert [entry.kind for entry in by_kind(entries, "arrive")] == ["arrive"]
    assert len(by_train(entries, "T01")) == 2
    assert kinds(entries) == ["arrive", "depart", "gap_probe"]
    assert count_by_kind(entries, "arrive") == 1
    assert last(entries).kind == "gap_probe"
    assert latest_by_kind(entries, "arrive").train_id == "T01"
    replay = log.replay()
    assert len(replay) == 3
    assert log.journal.count() == 3
    assert len(log.journal.segments()) == 2
    assert log.summary()["by_kind"]["arrive"] == 1
    assert "arrive" in log.dump()
    assert [event.action for event in seen] == ["gap_probe"]


def test_audit_rejects_empty_kind(tmp_path):
    log, _bus, _clock = _log(tmp_path)
    try:
        log.record("", "", "")
    except Exception as error:  # noqa: BLE001 - 只验证类型
        assert type(error).__name__ == "RailError"
    else:  # pragma: no cover - 不应走到这里
        raise AssertionError("空动作类型必须被拒绝")


def test_audit_timeline_orders_by_time(tmp_path):
    log, _bus, clock = _log(tmp_path)
    log.record("arrive", "T01", "ST1", at=100.0)
    clock.advance(5)
    log.record("depart", "T01", "ST1", at=105.0)
    timeline = build_timeline(log.list(), "T01")
    assert [item["kind"] for item in timeline] == ["arrive", "depart"]
    assert timeline[0]["step"] == 1


def test_json_store_atomic_roundtrip(tmp_path):
    store = JsonStore(str(tmp_path))
    store.write("station/ST1/layout", {"zones": 4})
    assert store.exists("station/ST1/layout") is True
    assert store.read("station/ST1/layout") == {"zones": 4}
    assert store.list_ids() == ["station/ST1/layout"]
    assert store.remove("station/ST1/layout") is True
    assert store.remove("station/ST1/layout") is False
    assert store.read("station/ST1/layout") is None


def test_journal_segments_roll(tmp_path):
    journal = JsonlJournal(str(tmp_path), "audit", segment_limit=2)
    for index in range(5):
        journal.append({"index": index})
    assert journal.count() == 5
    assert len(journal.segments()) == 3
    assert journal.active_segment() == 2
    assert [item["index"] for item in journal.read_segment(0)] == [0, 1]
    assert len(journal.read_all()) == 5
    assert journal.read_segment(9) == []
    assert journal.topic == "audit" and journal.segment_limit == 2

def test_audit_chain_links_records_and_archives_by_count(tmp_path):
    journal = ChainedJsonlJournal(str(tmp_path), "audit", segment_limit=2)
    first = journal.append({"id": "a", "kind": "arrive"})
    second = journal.append({"id": "b", "kind": "depart"})
    third = journal.append({"id": "c", "kind": "gap"})
    journal.append({"id": "d", "kind": "gap"})
    journal.append({"id": "e", "kind": "gap"})
    assert first["seq"] == 1
    assert first["prev_digest"] == "GENESIS"
    assert second["prev_digest"] == first["digest"]
    assert third["prev_digest"] == second["digest"]
    assert len(journal.segments()) == 3
    assert journal.sealed_segment_count() == 2
    manifest_path = tmp_path / "audit-00000.manifest.json"
    assert manifest_path.is_file()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["records"] == 2
    assert manifest["first_seq"] == 1
    assert manifest["last_seq"] == 2
    second_manifest_path = tmp_path / "audit-00001.manifest.json"
    second_manifest = json.loads(second_manifest_path.read_text(encoding="utf-8"))
    assert second_manifest["prev_manifest_digest"] == manifest["digest"]
    assert manifest["segment_digest"]
    assert manifest["prev_manifest_digest"] == "GENESIS"
    anchor_path = tmp_path / ".audit-manifest-anchor.jsonl"
    assert manifest["digest"] in anchor_path.read_text(encoding="utf-8")
    report = journal.verify_report()
    assert report["ok"] is True
    assert report["segments_checked"][0]["sealed"] is True
    assert report["segments_checked"][2]["records"] == 1


def test_audit_chain_detects_first_bad_record_and_blocks_writes(tmp_path):
    journal = ChainedJsonlJournal(str(tmp_path), "audit", segment_limit=2)
    for index in range(4):
        journal.append({"id": f"a{index}", "kind": "arrive"})
    target = tmp_path / "audit-00000.jsonl"
    target.chmod(0o600)
    lines = target.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[1])
    tampered["record"]["kind"] = "tampered"
    lines[1] = json.dumps(tampered, ensure_ascii=False)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")

    reopened = ChainedJsonlJournal(str(tmp_path), "audit", segment_limit=2)
    report = reopened.verify_report()
    assert report["ok"] is False
    assert report["first_bad"]["segment"] == 0
    assert report["first_bad"]["record_index"] == 1
    assert report["first_bad"]["seq"] == 2
    assert report["first_bad"]["kind"] == "digest_mismatch"
    assert report["first_bad"]["expected_digest"]
    assert report["first_bad"]["actual_digest"]
    try:
        reopened.append({"id": "x", "kind": "arrive"})
    except StorageError as error:
        assert "阻断写入" in error.message
    else:  # pragma: no cover
        raise AssertionError("断链后必须阻断追加")


def test_audit_chain_detects_tampered_archive_manifest(tmp_path):
    journal = ChainedJsonlJournal(str(tmp_path), "audit", segment_limit=2)
    journal.append({"id": "a", "kind": "arrive"})
    journal.append({"id": "b", "kind": "depart"})
    manifest_path = tmp_path / "audit-00000.manifest.json"
    manifest_path.chmod(0o600)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["records"] = 3
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    report = ChainedJsonlJournal(str(tmp_path), "audit", segment_limit=2).verify_report()
    assert report["ok"] is False
    assert report["first_bad"]["segment"] == 0
    assert report["first_bad"]["kind"] == "manifest_mismatch"


def test_audit_chain_migrates_legacy_plain_jsonl(tmp_path):
    first = {"id": "old1", "kind": "arrive", "at": 1}
    second = {"id": "old2", "kind": "depart", "at": 2}
    third = {"id": "old3", "kind": "gap", "at": 3}
    (tmp_path / "audit-00000.jsonl").write_text(
        "".join(json.dumps(item) + "\n" for item in [first, second]), encoding="utf-8"
    )
    (tmp_path / "audit-00001.jsonl").write_text(
        json.dumps(third) + "\n", encoding="utf-8"
    )
    journal = ChainedJsonlJournal(str(tmp_path), "audit", segment_limit=2)
    assert journal.count() == 3
    assert journal.read_segment(0) == [first, second]
    assert journal.verify_report()["ok"] is True
    assert (tmp_path / "audit-00000.jsonl.legacy").is_file()
    assert (tmp_path / "audit-00001.jsonl.legacy").is_file()
    next_record = journal.append({"id": "new", "kind": "arrive"})
    assert next_record["seq"] == 4
    assert next_record["prev_digest"] == journal.read_all_raw()[2]["digest"]


def test_audit_chain_recovers_from_trailing_partial_write(tmp_path):
    journal = ChainedJsonlJournal(str(tmp_path), "audit", segment_limit=2)
    for index in range(3):
        journal.append({"id": f"a{index}", "kind": "arrive"})
    with open(tmp_path / "audit-00001.jsonl", "a", encoding="utf-8") as handle:
        handle.write('{"record": {"id": "partial')
    recovered = ChainedJsonlJournal(str(tmp_path), "audit", segment_limit=2)
    assert recovered.count() == 3
    assert recovered.integrity_summary()["quarantined_parts"] == 1
    assert recovered.verify_report()["ok"] is True
    envelope = recovered.append({"id": "a3", "kind": "arrive"})
    assert envelope["seq"] == 4
    assert envelope["prev_digest"] == recovered.read_all_raw()[-2]["digest"]


def test_audit_chain_restores_history_and_sequence(tmp_path):
    bus = EventBus()
    clock = ManualClock()
    first_log = AuditLog(clock, bus, ChainedJsonlJournal(str(tmp_path), "audit", segment_limit=2))
    first_log.record("arrive", "T01", "ST1")
    first_log.record("depart", "T01", "ST1")
    reopened_log = AuditLog(clock, bus, ChainedJsonlJournal(str(tmp_path), "audit", segment_limit=2))
    assert len(reopened_log.list()) == 2
    entry = reopened_log.record("gap_probe", "T01", "ST1")
    assert entry.seq == 3
    assert entry.prev_digest == reopened_log.list()[1].digest
    assert reopened_log.verify()["ok"] is True


def test_audit_chain_refuses_missing_segment(tmp_path):
    journal = ChainedJsonlJournal(str(tmp_path), "audit", segment_limit=2)
    for index in range(5):
        journal.append({"id": f"a{index}", "kind": "arrive"})
    (tmp_path / "audit-00000.jsonl").unlink()
    (tmp_path / "audit-00000.manifest.json").unlink()
    reopened = ChainedJsonlJournal(str(tmp_path), "audit", segment_limit=2)
    assert reopened.healthy is False
    assert reopened.integrity_summary()["issue"]["kind"] == "missing_segment"
    audit_log = AuditLog(ManualClock(), EventBus(), reopened)
    assert audit_log.summary()["chain_healthy"] is False
    try:
        audit_log.record("arrive", "T01", "ST1")
    except StorageError as error:
        assert "阻断写入" in error.message
    else:  # pragma: no cover
        raise AssertionError("缺段时平台审计组件不能继续写入")


def test_command_log_queue(tmp_path):
    log = CommandLog(JsonStore(str(tmp_path)))
    log.append(DoorCommand(id="c1", train_id="T01", kind="open", epoch=log.epoch))
    log.append(DoorCommand(id="c2", train_id="T01", kind="close", epoch=log.epoch, station_id="ST1"))
    assert log.ids("T01") == ["c1", "c2"]
    assert log.total_queued() == 2
    assert log.pending("T01")[1].station_id == "ST1"
    assert log.clear("T01") == 2
    assert log.epoch == 1
    assert log.pending("T01") == []


def test_store_metrics_summarises(tmp_path):
    store = JsonStore(str(tmp_path))
    store.write("a/one", {"x": 1})
    journal = JsonlJournal(store.root, "audit", segment_limit=10)
    journal.append({"x": 1})
    metrics = StoreMetrics(store.root)
    summary = metrics.summary()
    assert summary["files"] >= 2
    assert summary["audit_segments"] == 1
    assert metrics.usage("a").files == 1
    assert metrics.root == store.root
