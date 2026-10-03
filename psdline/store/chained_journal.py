"""带哈希链与归档摘要的分段 JSONL 流水。

每个逻辑主题仍然使用 ``<topic>-00000.jsonl`` 这样的分段文件，但每条记录外面包一层
固定顺序的信封：``seq`` 给出全链序号，``prev_digest`` 指向前一条记录的 SHA-256
摘要，``digest`` 固定本条内容。段写满后同步生成 ``<topic>-00000.manifest.json``，
其中记录本段首尾摘要和归档清单自身的摘要；已归档段不再改写。

启动恢复会迁移旧版“裸 JSONL”数据，并处理掉电时可能留下的最后一行半截记录。真正
的哈希不一致、缺段或归档摘要不匹配会把日志置为不健康，之后追加直接失败，防止在
被破坏的链后面继续写入。
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
from dataclasses import dataclass, field
from typing import Any

from ..errors import StorageError

GENESIS_DIGEST = "GENESIS"
CHAIN_VERSION = 1
_ENCODING = "utf-8"


@dataclass(frozen=True)
class ChainIssue:
    """一次链校验发现的首个问题。"""

    segment: int
    kind: str
    message: str
    seq: int | None = None
    record_index: int | None = None
    path: str = ""
    expected_digest: str = ""
    actual_digest: str = ""

    def as_dict(self) -> dict:
        return {
            "segment": self.segment,
            "kind": self.kind,
            "message": self.message,
            "seq": self.seq,
            "record_index": self.record_index,
            "path": self.path,
            "expected_digest": self.expected_digest,
            "actual_digest": self.actual_digest,
        }


@dataclass
class SegmentCheck:
    """一个段的校验结果。"""

    segment: int
    path: str
    records: int
    sealed: bool
    first_seq: int | None = None
    last_seq: int | None = None
    first_digest: str = ""
    last_digest: str = ""
    expected_digest: str = ""
    actual_digest: str = ""
    ok: bool = True
    issue: ChainIssue | None = None
    manifest_path: str = ""

    def as_dict(self) -> dict:
        return {
            "segment": self.segment,
            "path": self.path,
            "records": self.records,
            "sealed": self.sealed,
            "first_seq": self.first_seq,
            "last_seq": self.last_seq,
            "first_digest": self.first_digest,
            "last_digest": self.last_digest,
            "expected_digest": self.expected_digest,
            "actual_digest": self.actual_digest,
            "ok": self.ok,
            "issue": None if self.issue is None else self.issue.as_dict(),
            "manifest_path": self.manifest_path,
        }


def canonical_json(payload: Any) -> bytes:
    """返回跨 Python 进程稳定的 JSON 字节序列。"""

    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode(_ENCODING)


def digest_payload(payload: Any) -> str:
    """计算稳定 JSON 表示的 SHA-256 摘要。"""

    try:
        raw = canonical_json(payload)
    except (TypeError, ValueError) as error:
        raise StorageError(f"审计记录包含不可序列化内容: {error}", component="store") from error
    return hashlib.sha256(raw).hexdigest()


def record_digest(seq: int, prev_digest: str, payload: dict) -> str:
    """计算链上第 ``seq`` 条记录的摘要。"""

    return digest_payload(
        {
            "version": CHAIN_VERSION,
            "seq": seq,
            "prev_digest": prev_digest,
            "record": payload,
        }
    )


@dataclass
class _State:
    count: int = 0
    active_segment: int = 0
    last_digest: str = GENESIS_DIGEST
    sealed_segments: int = 0
    last_manifest_digest: str = GENESIS_DIGEST
    healthy: bool = True
    issue: ChainIssue | None = None
    recovery: list[dict] = field(default_factory=list)
    records: list[dict] = field(default_factory=list)


class ChainedJsonlJournal:
    """按段追加、逐记录哈希链接、按段固定摘要的 JSONL 存储。"""

    def __init__(self, root: str, topic: str, segment_limit: int = 512) -> None:
        self._root = os.path.abspath(root)
        self._topic = topic
        self._segment_limit = max(1, segment_limit)
        self._lock = threading.RLock()
        os.makedirs(self._root, exist_ok=True)
        self._quarantine_dir = os.path.join(self._root, f".{self._topic}-quarantine")
        os.makedirs(self._quarantine_dir, exist_ok=True)
        self._state = self._recover()

    @property
    def topic(self) -> str:
        return self._topic

    @property
    def segment_limit(self) -> int:
        return self._segment_limit

    @property
    def healthy(self) -> bool:
        with self._lock:
            return self._state.healthy

    def _segment_path(self, index: int) -> str:
        return os.path.join(self._root, f"{self._topic}-{index:05d}.jsonl")

    def _manifest_path(self, index: int) -> str:
        return os.path.join(self._root, f"{self._topic}-{index:05d}.manifest.json")

    def _anchor_path(self) -> str:
        return os.path.join(self._root, f".{self._topic}-manifest-anchor.jsonl")

    def _segment_index(self, name: str) -> int | None:
        match = re.fullmatch(rf"{re.escape(self._topic)}-(\d{{5}})\.jsonl", name)
        if match is None:
            return None
        return int(match.group(1))

    def _fsync_dir(self, path: str) -> None:
        try:
            handle = os.open(path, os.O_RDONLY)
            try:
                os.fsync(handle)
            finally:
                os.close(handle)
        except OSError:
            # 部分文件系统不支持目录 fsync；数据文件自身已经 fsync。
            pass

    def _fsync_path(self, path: str) -> None:
        handle = os.open(path, os.O_RDONLY)
        try:
            os.fsync(handle)
        finally:
            os.close(handle)

    def _read_lines(self, path: str) -> tuple[list[str], bool]:
        with open(path, "r", encoding=_ENCODING, newline="") as handle:
            raw = handle.read()
        lines = raw.splitlines()
        valid = [line for line in lines if line.strip()]
        torn = bool(raw and not raw.endswith("\n") and lines and lines[-1].strip())
        return valid, torn

    def _load_lines(self, path: str) -> tuple[list[dict], bool, int | None]:
        lines, torn = self._read_lines(path)
        records: list[dict] = []
        for line_index, line in enumerate(lines):
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                return records, torn, line_index
            if not isinstance(item, dict):
                return records, torn, line_index
            records.append(item)
        return records, torn, None

    def _is_chain_record(self, item: dict) -> bool:
        return all(key in item for key in ("version", "seq", "prev_digest", "record", "digest"))

    def _discover_segments(self) -> list[tuple[int, str]]:
        found: list[tuple[int, str]] = []
        for name in os.listdir(self._root):
            index = self._segment_index(name)
            if index is not None:
                found.append((index, os.path.join(self._root, name)))
        found.sort(key=lambda item: item[0])
        return found

    def _migrate_legacy(self) -> None:
        """把旧版裸 JSONL 迁移成链；旧文件保留为不可写的 .legacy 备份。"""

        discovered: list[tuple[int, str]] = []
        for name in os.listdir(self._root):
            index = self._segment_index(name)
            if index is not None:
                discovered.append((index, os.path.join(self._root, name)))
        discovered.sort(key=lambda item: item[0])
        prev_digest = GENESIS_DIGEST

        for index, target in discovered:
            source = target
            resume_backup = False
            if not os.path.isfile(target):
                backup = target + ".legacy"
                if os.path.isfile(backup):
                    source = backup
                    resume_backup = True
                else:
                    # 段文件和可恢复的旧备份都不存在；交给后续缺段检查处理。
                    continue
            if not os.path.isfile(source):
                continue
            records, torn, bad_line = self._load_lines(source)
            if records and any(self._is_chain_record(item) for item in records):
                # 已有链段的半截尾行交给恢复逻辑隔离，不能误判成旧格式迁移。
                prev_digest = str(records[-1].get("digest", prev_digest))
                continue
            if bad_line is not None or torn:
                raise StorageError(
                    f"旧审计段 {source} 存在不完整或非法 JSON，无法安全迁移",
                    component="store",
                )
            if not records:
                if resume_backup:
                    with open(target, "w", encoding=_ENCODING):
                        pass
                continue
            legacy_path = target + ".legacy"
            if not resume_backup:
                if os.path.exists(legacy_path):
                    raise StorageError(f"旧审计备份已存在: {legacy_path}", component="store")
                os.replace(target, legacy_path)
            else:
                legacy_path = source
            try:
                os.chmod(legacy_path, 0o440)
            except OSError:
                pass
            try:
                with open(target, "w", encoding=_ENCODING) as handle:
                    for offset, record in enumerate(records, start=1):
                        seq = index * self._segment_limit + offset
                        digest = record_digest(seq, prev_digest, record)
                        envelope = {
                            "version": CHAIN_VERSION,
                            "seq": seq,
                            "prev_digest": prev_digest,
                            "record": record,
                            "digest": digest,
                        }
                        handle.write(json.dumps(envelope, ensure_ascii=False) + "\n")
                        prev_digest = digest
                    handle.flush()
                    os.fsync(handle.fileno())
                self._fsync_dir(self._root)
            except OSError as error:
                raise StorageError(f"迁移旧审计流水失败: {error}", component="store") from error

    def _quarantine_tail(self, path: str, line_index: int, reason: str) -> dict:
        records, torn, _bad = self._load_lines(path)
        valid_lines = [line for line in self._read_lines(path)[0] if line.strip()]
        if line_index < len(valid_lines):
            partial = valid_lines[line_index]
        elif torn and valid_lines:
            partial = valid_lines[-1]
        else:
            partial = ""
        keep_lines = valid_lines[:line_index] if line_index < len(valid_lines) else valid_lines[:-1]
        segment_name = os.path.basename(path)
        quarantine_path = os.path.join(
            self._quarantine_dir,
            f"{segment_name}.line-{line_index:010d}.partial",
        )
        with open(quarantine_path, "w", encoding=_ENCODING) as handle:
            handle.write(partial)
            handle.flush()
            os.fsync(handle.fileno())

        directory = os.path.dirname(path)
        temporary = tempfile.NamedTemporaryFile(
            "w",
            encoding=_ENCODING,
            dir=directory,
            prefix=".audit-recovery.",
            suffix=".tmp",
            delete=False,
        )
        try:
            with temporary:
                for line in keep_lines:
                    temporary.write(line + "\n")
                temporary.flush()
                os.fsync(temporary.fileno())
            os.replace(temporary.name, path)
        finally:
            if os.path.exists(temporary.name):
                os.unlink(temporary.name)
        self._fsync_dir(directory)
        self._fsync_dir(self._quarantine_dir)
        event = {
            "path": path,
            "quarantine": quarantine_path,
            "line": line_index,
            "reason": reason,
        }
        return event

    def _recover(self) -> _State:
        try:
            self._migrate_legacy()
            segments = self._discover_segments()
            state = _State(active_segment=segments[-1][0] if segments else 0)
            expected_prev = GENESIS_DIGEST

            for expected_index, (index, path) in enumerate(segments):
                if index != expected_index:
                    state.healthy = False
                    state.issue = ChainIssue(
                        index,
                        "missing_segment",
                        f"段号不连续，期望 {expected_index}，实际 {index}",
                        path=path,
                    )
                    return state

                records, torn, bad_line = self._load_lines(path)
                expected_size = index * self._segment_limit
                if bad_line is not None:
                    # 最后活动段的最后一行可能在 write/fsync 之间崩溃；归档段不允许裁剪。
                    if index == segments[-1][0] and bad_line == len([line for line in self._read_lines(path)[0] if line.strip()]) - 1:
                        state.recovery.append(
                            self._quarantine_tail(path, bad_line, "malformed_json_tail")
                        )
                        records, torn, bad_line = self._load_lines(path)
                if bad_line is not None:
                    state.healthy = False
                    state.issue = ChainIssue(
                        index,
                        "malformed_record",
                        f"第 {bad_line} 行不是有效 JSON 对象",
                        record_index=bad_line,
                        path=path,
                    )
                    return state
                if torn:
                    if index == segments[-1][0] and records:
                        line_index = len(self._read_lines(path)[0]) - 1
                        state.recovery.append(
                            self._quarantine_tail(path, line_index, "missing_trailing_newline")
                        )
                        records, _torn, bad_line = self._load_lines(path)
                    elif not records and index == segments[-1][0]:
                        # 空文件无已确认记录，截断为正常空段即可。
                        with open(path, "w", encoding=_ENCODING):
                            pass
                    else:
                        state.healthy = False
                        state.issue = ChainIssue(
                            index,
                            "torn_archive",
                            "已归档段出现缺少换行的半截记录",
                            path=path,
                        )
                        return state
                if not records and index != segments[-1][0]:
                    state.healthy = False
                    state.issue = ChainIssue(
                        index,
                        "empty_archive",
                        "已归档的非尾段为空",
                        path=path,
                    )
                    return state

                for offset, item in enumerate(records):
                    seq = expected_size + offset + 1
                    issue = self._record_issue(item, seq, expected_prev, index, offset, path)
                    if issue is not None:
                        state.healthy = False
                        state.issue = issue
                        return state
                    expected_prev = str(item["digest"])
                    state.records.append(item)

                state.count += len(records)
                state.last_digest = expected_prev
                state.active_segment = index
                manifest_path = self._manifest_path(index)
                if os.path.isfile(manifest_path):
                    issue = self._manifest_issue(index, path, records, manifest_path, expected_prev)
                    if issue is not None:
                        state.healthy = False
                        state.issue = issue
                        return state
                    state.sealed_segments += 1
                    state.last_manifest_digest = str(self._read_manifest_digest(manifest_path))
                elif len(records) == self._segment_limit:
                    # 段已写满但归档摘要可能尚未落盘，按当前已确认链补做。
                    manifest_path = self._write_manifest(
                        index,
                        path,
                        records,
                        expected_prev,
                        recovered=True,
                        prev_manifest_digest=state.last_manifest_digest,
                    )
                    state.sealed_segments += 1
                    state.last_manifest_digest = str(self._read_manifest_digest(manifest_path))
                elif state.sealed_segments != index:
                    state.healthy = False
                    state.issue = ChainIssue(
                        index,
                        "missing_manifest",
                        f"未满段 {index} 前已有后续段，但缺少归档摘要",
                        path=path,
                    )
                    return state
            return state
        except StorageError as error:
            state = _State(healthy=False)
            state.issue = ChainIssue(0, "recovery_failed", error.message)
            return state

    def _record_issue(
        self,
        item: dict,
        expected_seq: int,
        expected_prev: str,
        segment: int,
        offset: int,
        path: str,
    ) -> ChainIssue | None:
        if not self._is_chain_record(item):
            return ChainIssue(
                segment,
                "record_format",
                "记录缺少链信封字段",
                seq=expected_seq,
                record_index=offset,
                path=path,
            )
        if item.get("version") != CHAIN_VERSION:
            return ChainIssue(
                segment,
                "version_mismatch",
                f"链版本不是 {CHAIN_VERSION}",
                seq=expected_seq,
                record_index=offset,
                path=path,
            )
        if item.get("seq") != expected_seq:
            return ChainIssue(
                segment,
                "sequence_mismatch",
                f"序号应为 {expected_seq}，实际 {item.get('seq')}",
                seq=expected_seq,
                record_index=offset,
                path=path,
            )
        if item.get("prev_digest") != expected_prev:
            return ChainIssue(
                segment,
                "broken_link",
                "前一条记录摘要不匹配",
                seq=expected_seq,
                record_index=offset,
                path=path,
                expected_digest=expected_prev,
                actual_digest=str(item.get("prev_digest", "")),
            )
        actual_digest = digest_payload(
            {
                "version": item["version"],
                "seq": item["seq"],
                "prev_digest": item["prev_digest"],
                "record": item["record"],
            }
        )
        if item.get("digest") != actual_digest:
            return ChainIssue(
                segment,
                "digest_mismatch",
                "当前记录内容摘要不匹配",
                seq=expected_seq,
                record_index=offset,
                path=path,
                expected_digest=actual_digest,
                actual_digest=str(item.get("digest", "")),
            )
        return None

    def _manifest_payload(
        self,
        index: int,
        path: str,
        records: list[dict],
        last_digest: str,
        recovered: bool = False,
        prev_manifest_digest: str = GENESIS_DIGEST,
    ) -> dict:
        first = records[0]
        payload = {
            "version": CHAIN_VERSION,
            "topic": self._topic,
            "segment": index,
            "path": os.path.basename(path),
            "records": len(records),
            "first_seq": first["seq"],
            "last_seq": records[-1]["seq"],
            "first_digest": first["digest"],
            "last_digest": last_digest,
            "prev_record_digest": str(first.get("prev_digest", GENESIS_DIGEST)),
            "segment_digest": digest_payload([self._manifest_record_view(item) for item in records]),
            "prev_manifest_digest": prev_manifest_digest,
            "recovered": recovered,
        }
        payload["digest"] = digest_payload(
            {key: value for key, value in payload.items() if key != "digest"}
        )
        return payload

    @staticmethod
    def _manifest_record_view(item: dict) -> dict:
        return {
            "seq": item["seq"],
            "prev_digest": item["prev_digest"],
            "digest": item["digest"],
            "record": item["record"],
            "version": item["version"],
        }

    def _write_manifest(
        self,
        index: int,
        path: str,
        records: list[dict],
        last_digest: str,
        recovered: bool = False,
        prev_manifest_digest: str = GENESIS_DIGEST,
    ) -> str:
        manifest = self._manifest_payload(
            index,
            path,
            records,
            last_digest,
            recovered,
            prev_manifest_digest,
        )
        manifest_path = self._manifest_path(index)
        directory = os.path.dirname(manifest_path)
        temporary = tempfile.NamedTemporaryFile(
            "w",
            encoding=_ENCODING,
            dir=directory,
            prefix=".audit-manifest.",
            suffix=".tmp",
            delete=False,
        )
        try:
            with temporary:
                json.dump(manifest, temporary, ensure_ascii=False, indent=2)
                temporary.flush()
                os.fsync(temporary.fileno())
            os.replace(temporary.name, manifest_path)
        except OSError as error:
            if os.path.exists(temporary.name):
                os.unlink(temporary.name)
            raise StorageError(f"写入审计归档摘要失败: {error}", component="store") from error
        self._fsync_dir(directory)
        try:
            self._append_manifest_anchor(index, str(manifest["digest"]))
        except OSError as error:
            raise StorageError(f"写入审计归档锚点失败: {error}", component="store") from error
        try:
            os.chmod(path, 0o440)
            os.chmod(manifest_path, 0o440)
        except OSError:
            # chmod 在特殊文件系统上可能失败；摘要链仍然提供不可变性证据。
            pass
        return manifest_path

    @staticmethod
    def _read_manifest(path: str) -> dict:
        with open(path, "r", encoding=_ENCODING) as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            raise StorageError(f"归档摘要格式错误: {path}", component="store")
        return payload

    def _read_manifest_digest(self, path: str) -> str:
        return str(self._read_manifest(path).get("digest", ""))

    def _manifest_self_digest(self, manifest: dict) -> str:
        return digest_payload({key: value for key, value in manifest.items() if key != "digest"})

    def _anchor_entries(self) -> tuple[list[dict], bool]:
        path = self._anchor_path()
        if not os.path.isfile(path):
            return [], False
        with open(path, "r", encoding=_ENCODING) as handle:
            raw = handle.read()
        torn = bool(raw and not raw.endswith("\n"))
        entries: list[dict] = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as error:
                raise StorageError(f"归档锚点包含非法 JSON: {error}", component="store") from error
            if isinstance(item, dict):
                entries.append(item)
        return entries, torn

    def _append_manifest_anchor(self, index: int, manifest_digest: str) -> str:
        path = self._anchor_path()
        with open(path, "a", encoding=_ENCODING) as handle:
            handle.write(
                json.dumps({"segment": index, "digest": manifest_digest}, ensure_ascii=False) + "\n"
            )
            handle.flush()
            os.fsync(handle.fileno())
        self._fsync_dir(self._root)
        return path

    def _anchor_issue(self, index: int, manifest_digest: str) -> ChainIssue | None:
        anchor_path = self._anchor_path()
        try:
            entries, torn = self._anchor_entries()
        except (OSError, json.JSONDecodeError, StorageError) as error:
            return ChainIssue(index, "anchor_unreadable", str(error), path=anchor_path)
        if torn:
            return ChainIssue(index, "anchor_torn", "归档锚点最后一行不完整", path=anchor_path)
        anchored: dict[int, str] = {}
        for item in entries:
            try:
                segment = int(item.get("segment", -1))
            except (TypeError, ValueError):
                segment = -1
            anchored.setdefault(segment, str(item.get("digest", "")))
        matching = []
        for item in entries:
            try:
                segment = int(item.get("segment", -1))
            except (TypeError, ValueError):
                segment = -1
            if segment == index:
                matching.append(str(item.get("digest", "")))
        if len(matching) > 1:
            return ChainIssue(index, "anchor_duplicate", "归档锚点中同一段出现多次", path=anchor_path)
        if matching:
            if matching[0] != manifest_digest:
                return ChainIssue(index, "anchor_mismatch", "归档摘要与锚点不一致", path=anchor_path)
            return None
        # 归档清单已落盘而锚点缺失，可能正处在两个原子操作之间；允许补锚。
        for previous in range(index):
            if previous not in anchored:
                return ChainIssue(
                    previous,
                    "anchor_missing",
                    f"缺少段 {previous} 的归档锚点",
                    path=anchor_path,
                )
        try:
            path = self._append_manifest_anchor(index, manifest_digest)
        except OSError as error:
            return ChainIssue(index, "anchor_write_failed", str(error), path=anchor_path)
        if hasattr(self, "_state"):
            self._state.recovery.append(
                {"path": path, "segment": index, "reason": "manifest_anchor_rebuilt"}
            )
        return None

    def _manifest_issue(
        self,
        index: int,
        path: str,
        records: list[dict],
        manifest_path: str,
        last_digest: str,
    ) -> ChainIssue | None:
        try:
            with open(manifest_path, "r", encoding=_ENCODING) as handle:
                manifest = json.load(handle)
        except (OSError, json.JSONDecodeError) as error:
            return ChainIssue(index, "manifest_unreadable", str(error), path=manifest_path)
        if not isinstance(manifest, dict):
            return ChainIssue(index, "manifest_format", "归档摘要不是 JSON 对象", path=manifest_path)
        prev_manifest_digest = GENESIS_DIGEST
        if index > 0:
            previous_path = self._manifest_path(index - 1)
            try:
                with open(previous_path, "r", encoding=_ENCODING) as handle:
                    previous_manifest = json.load(handle)
            except (OSError, json.JSONDecodeError) as error:
                return ChainIssue(
                    index,
                    "previous_manifest_unreadable",
                    f"无法读取前序归档摘要: {error}",
                    path=previous_path,
                )
            if not isinstance(previous_manifest, dict) or not previous_manifest.get("digest"):
                return ChainIssue(
                    index,
                    "previous_manifest_format",
                    "前序归档摘要缺少自身摘要",
                    path=previous_path,
                )
            prev_manifest_digest = str(previous_manifest["digest"])
        expected = self._manifest_payload(
            index,
            path,
            records,
            last_digest,
            bool(manifest.get("recovered")),
            prev_manifest_digest,
        )
        if manifest.get("prev_manifest_digest") != prev_manifest_digest:
            return ChainIssue(index, "manifest_chain_broken", "前一段归档摘要不匹配", path=manifest_path)
        for key, value in expected.items():
            if manifest.get(key) != value:
                return ChainIssue(
                    index,
                    "manifest_mismatch",
                    f"归档摘要字段 {key} 不一致",
                    path=manifest_path,
                )
        return self._anchor_issue(index, str(manifest["digest"]))

    def append(self, record: dict) -> dict:
        """追加一条裸业务记录，自动生成序号、链接摘要并返回链信封。"""

        if not isinstance(record, dict):
            raise StorageError("审计记录必须是 JSON 对象", component="store")
        with self._lock:
            if not self._state.healthy:
                raise StorageError(
                    f"审计链不健康，已阻断写入: {self._state.issue.message if self._state.issue else '未知原因'}",
                    component="store",
                )
            # 上一次追加可能已写完整段，但在归档摘要落盘前崩溃。
            if self._state.count % self._segment_limit == 0:
                active = self._state.active_segment
                active_path = self._segment_path(active)
                if (
                    os.path.isfile(active_path)
                    and not os.path.isfile(self._manifest_path(active))
                    and len(self.read_segment_raw(active)) == self._segment_limit
                ):
                    records = self.read_segment_raw(active)
                    manifest_path = self._write_manifest(
                        active,
                        active_path,
                        records,
                        self._state.last_digest,
                        recovered=True,
                        prev_manifest_digest=self._state.last_manifest_digest,
                    )
                    self._state.sealed_segments = active + 1
                    self._state.last_manifest_digest = self._read_manifest_digest(manifest_path)
                    self._state.active_segment = active + 1
            seq = self._state.count + 1
            index = (seq - 1) // self._segment_limit
            path = self._segment_path(index)
            prev_digest = self._state.last_digest
            digest = record_digest(seq, prev_digest, record)
            envelope = {
                "version": CHAIN_VERSION,
                "seq": seq,
                "prev_digest": prev_digest,
                "record": record,
                "digest": digest,
            }
            try:
                with open(path, "a", encoding=_ENCODING) as handle:
                    handle.write(json.dumps(envelope, ensure_ascii=False, allow_nan=False) + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                self._fsync_dir(self._root)
            except (OSError, TypeError, ValueError) as error:
                raise StorageError(f"追加审计流水失败: {error}", component="store") from error

            self._state.count = seq
            self._state.active_segment = index
            self._state.last_digest = digest
            if seq % self._segment_limit == 0:
                manifest_path = self._write_manifest(
                    index,
                    path,
                    self.read_segment_raw(index),
                    digest,
                    prev_manifest_digest=self._state.last_manifest_digest,
                )
                self._state.sealed_segments = index + 1
                self._state.last_manifest_digest = self._read_manifest_digest(manifest_path)
            return envelope

    def _mark_unhealthy(self, issue: ChainIssue | None) -> None:
        if issue is not None and self._state.healthy:
            self._state.healthy = False
            self._state.issue = issue

    def _verify_segment(
        self,
        index: int,
        path: str,
        expected_prev: str,
        *,
        compare_manifest: bool = True,
        validate_manifest: bool = True,
    ) -> tuple[SegmentCheck, str]:
        result = SegmentCheck(segment=index, path=path, records=0, sealed=False)
        records, torn, bad_line = self._load_lines(path)
        result.records = len(records)
        manifest_path = self._manifest_path(index)
        result.sealed = os.path.isfile(manifest_path)
        result.manifest_path = manifest_path
        result.expected_digest = expected_prev
        if bad_line is not None:
            result.ok = False
            result.issue = ChainIssue(
                index,
                "malformed_record",
                f"第 {bad_line} 行不是有效 JSON 对象",
                record_index=bad_line,
                path=path,
            )
            return result, expected_prev
        if torn:
            result.ok = False
            result.issue = ChainIssue(index, "torn_record", "最后一条记录缺少换行", path=path)
            return result, expected_prev

        for offset, item in enumerate(records):
            expected_seq = index * self._segment_limit + offset + 1
            issue = self._record_issue(item, expected_seq, expected_prev, index, offset, path)
            if issue is not None:
                result.ok = False
                result.issue = issue
                return result, expected_prev
            expected_prev = str(item["digest"])
            if offset == 0:
                result.first_seq = item["seq"]
                result.first_digest = item["digest"]
        if records:
            result.last_seq = records[-1]["seq"]
            result.last_digest = records[-1]["digest"]
            result.actual_digest = records[-1]["digest"]
        if validate_manifest and result.sealed:
            issue = (
                self._manifest_issue(index, path, records, manifest_path, expected_prev)
                if compare_manifest
                else self._anchor_issue(index, self._read_manifest_digest(manifest_path))
            )
            if issue is not None:
                result.ok = False
                result.issue = issue
        return result, expected_prev

    def _manifest_reference_issue(
        self,
        index: int,
        path: str,
        expected_prev: str,
    ) -> ChainIssue | None:
        manifest_path = self._manifest_path(index)
        try:
            manifest = self._read_manifest(manifest_path)
        except (OSError, json.JSONDecodeError, StorageError) as error:
            return ChainIssue(index, "manifest_unreadable", str(error), path=manifest_path)
        trusted_prev_manifest = GENESIS_DIGEST
        if index > 0:
            previous_path = self._manifest_path(index - 1)
            try:
                previous_manifest = self._read_manifest(previous_path)
            except (OSError, json.JSONDecodeError, StorageError) as error:
                return ChainIssue(index, "previous_manifest_unreadable", str(error), path=previous_path)
            trusted_prev_manifest = self._manifest_self_digest(previous_manifest)
            anchor_issue = self._anchor_issue(index - 1, trusted_prev_manifest)
            if anchor_issue is not None:
                return anchor_issue
        if manifest.get("prev_manifest_digest") != trusted_prev_manifest:
            return ChainIssue(index, "manifest_chain_broken", "归档摘要链不匹配", path=manifest_path)
        if manifest.get("last_digest") != expected_prev:
            return ChainIssue(
                index,
                "manifest_chain_position",
                "归档段尾部摘要与当前段前驱不一致",
                path=manifest_path,
                expected_digest=expected_prev,
                actual_digest=str(manifest.get("last_digest", "")),
            )
        return None

    def verify_segment(self, index: int) -> SegmentCheck:
        """校验指定段；段不存在时返回失败结果而不抛异常。"""

        with self._lock:
            path = self._segment_path(index)
            if not os.path.isfile(path):
                result = SegmentCheck(index, path, 0, False)
                result.ok = False
                result.issue = ChainIssue(index, "missing_segment", "段文件不存在", path=path)
                return result
            expected_prev = GENESIS_DIGEST
            manifest_path = self._manifest_path(index)
            sealed = os.path.isfile(manifest_path)
            if index > 0:
                if not sealed:
                    # 未满活动段必须从起点重算，确保没有前序记录被删改。
                    for previous in range(index):
                        prior = self._segment_path(previous)
                        if not os.path.isfile(prior):
                            result = SegmentCheck(index, path, 0, False)
                            result.ok = False
                            result.issue = ChainIssue(
                                index,
                                "missing_segment",
                                f"缺少前序段 {previous}",
                            )
                            self._mark_unhealthy(result.issue)
                            return result
                        check, expected_prev = self._verify_segment(previous, prior, expected_prev)
                        if not check.ok:
                            self._mark_unhealthy(check.issue)
                            return check
                else:
                    previous_manifest_path = self._manifest_path(index - 1)
                    if not os.path.isfile(previous_manifest_path):
                        result = SegmentCheck(index, path, 0, True)
                        result.ok = False
                        result.issue = ChainIssue(
                            index,
                            "previous_manifest_missing",
                            f"缺少前序归档摘要 {index - 1}",
                            path=previous_manifest_path,
                        )
                        self._mark_unhealthy(result.issue)
                        return result
                    try:
                        previous_manifest = self._read_manifest(previous_manifest_path)
                        expected_prev = str(previous_manifest.get("last_digest", ""))
                    except (OSError, json.JSONDecodeError, StorageError) as error:
                        result = SegmentCheck(index, path, 0, True)
                        result.ok = False
                        result.issue = ChainIssue(
                            index,
                            "previous_manifest_unreadable",
                            str(error),
                            path=previous_manifest_path,
                        )
                        self._mark_unhealthy(result.issue)
                        return result
            check, target_last_digest = self._verify_segment(
                index,
                path,
                expected_prev,
                compare_manifest=not sealed or index == 0,
            )
            if index > 0 and check.ok and sealed:
                reference_issue = self._manifest_reference_issue(index, path, target_last_digest)
                if reference_issue is not None:
                    check.ok = False
                    check.issue = reference_issue
            if not check.ok:
                self._mark_unhealthy(check.issue)
            return check

    def verify(self) -> list[SegmentCheck]:
        """按段顺序校验全链，返回每段结果；首个错误段之后仍列出但不继续深链。"""

        with self._lock:
            results: list[SegmentCheck] = []
            expected_prev = GENESIS_DIGEST
            segments = self._discover_segments()
            for expected_index, item in enumerate(segments):
                index, path = item
                if index != expected_index:
                    check = SegmentCheck(index, path, 0, os.path.isfile(self._manifest_path(index)))
                    check.ok = False
                    check.issue = ChainIssue(
                        index,
                        "missing_segment",
                        f"段号不连续，期望 {expected_index}",
                        path=path,
                    )
                    results.append(check)
                    self._mark_unhealthy(check.issue)
                    break
                check, expected_prev = self._verify_segment(index, path, expected_prev)
                results.append(check)
                if not check.ok:
                    self._mark_unhealthy(check.issue)
                    break
            return results

    def verify_report(self) -> dict:
        """返回适合 API/控制台展示的全链校验报告。"""

        with self._lock:
            checks = self.verify()
            first_bad = next((item for item in checks if not item.ok), None)
            return {
                "ok": first_bad is None,
                "records": self._state.count,
                "active_segment": self._state.active_segment,
                "segments": len(self._discover_segments()),
                "sealed_segments": self._state.sealed_segments,
                "archive_policy": "record_count",
                "sealed_immutable": True,
                "quarantined_parts": self.quarantine_count(),
                "first_bad": None if first_bad is None or first_bad.issue is None else first_bad.issue.as_dict(),
                "segments_checked": [item.as_dict() for item in checks],
                "recovery": list(self._state.recovery),
            }

    def read_segment_raw(self, index: int) -> list[dict]:
        """读取一个段中的链信封。"""

        path = self._segment_path(index)
        if not os.path.isfile(path):
            return []
        records, torn, bad_line = self._load_lines(path)
        if torn or bad_line is not None:
            raise StorageError(f"审计段 {path} 存在未恢复的不完整记录", component="store")
        return records

    def read_segment(self, index: int) -> list[dict]:
        """读取一个段中的业务记录（去掉链信封）。"""

        return [dict(item["record"]) for item in self.read_segment_raw(index) if "record" in item]

    def read_all_raw(self) -> list[dict]:
        """按段顺序读取全部链信封。"""

        records: list[dict] = []
        for index, _path in self._discover_segments():
            records.extend(self.read_segment_raw(index))
        return records

    def read_all(self) -> list[dict]:
        """按段顺序读取全部业务记录。"""

        return [dict(item["record"]) for item in self.read_all_raw() if "record" in item]

    def segments(self) -> list[str]:
        """返回段文件路径（按段号升序）。"""

        with self._lock:
            return [path for _index, path in self._discover_segments()]

    def count(self) -> int:
        with self._lock:
            return self._state.count

    def active_segment(self) -> int:
        with self._lock:
            return self._state.active_segment

    def sealed_segment_count(self) -> int:
        with self._lock:
            return self._state.sealed_segments

    def recovered_records(self) -> list[dict]:
        """返回启动恢复时确认有效的链信封（损坏后仍可用于只读展示）。"""

        with self._lock:
            return list(self._state.records)

    def recovery_events(self) -> list[dict]:
        with self._lock:
            return list(self._state.recovery)

    def quarantine_count(self) -> int:
        try:
            return len([name for name in os.listdir(self._quarantine_dir) if os.path.isfile(os.path.join(self._quarantine_dir, name))])
        except OSError:
            return 0

    def integrity_summary(self) -> dict:
        with self._lock:
            return {
                "healthy": self._state.healthy,
                "records": self._state.count,
                "active_segment": self._state.active_segment,
                "sealed_segments": self._state.sealed_segments,
                "archive_policy": "record_count",
                "sealed_immutable": True,
                "quarantined_parts": self.quarantine_count(),
                "issue": None if self._state.issue is None else self._state.issue.as_dict(),
                "recovery": list(self._state.recovery),
            }
