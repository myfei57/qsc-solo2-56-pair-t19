"""分段 JSONL 流水日志。

流水只追加不重写，按 ``segment_limit`` 条一段滚动成 ``<topic>-00000.jsonl``、
``<topic>-00001.jsonl``…。审计回放需要按段读取，因此同时提供段号列表、单段读取
和全量读取三种入口。

链式审计在这一层之上做两件事：

* ``write_anchor``：段封存时把段头摘要固定到 ``<segment>.anchor.json``，先写
  同目录临时文件再原子替换，并对目录 ``fsync``，掉电不会留下半截锚点；锚点与
  段文件本身一样只写一次。
* ``seal_active`` / ``recover_tail``：支持显式封存（段满滚动之外的手动归档）与
  启动恢复（截掉活动段末尾未写完的半行）。

纯流水调用方（非链式）仍然只用 ``append``，行为与滚动规则保持不变。
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from typing import Any, Iterator

from ..errors import StorageError

ANCHOR_SUFFIX = ".anchor.json"
_MAX_SEGMENTS = 1 << 20


class JsonlJournal:
    """按段落写入的 JSONL 流水。"""

    def __init__(self, root: str, topic: str, segment_limit: int = 512) -> None:
        self._root = os.path.abspath(root)
        self._topic = topic
        self._segment_limit = max(1, segment_limit)
        self._lock = threading.RLock()
        os.makedirs(self._root, exist_ok=True)
        # 段列表只含磁盘上真实存在的段文件（0 行段也算实体，跳号空洞不算）。
        self._sizes = self._existing_sizes()
        if self._sizes:
            self._segment = self._sizes[-1][0]
            self._count = sum(size for _index, size in self._sizes)
        else:
            self._segment = 0
            self._count = 0

    @property
    def topic(self) -> str:
        return self._topic

    @property
    def segment_limit(self) -> int:
        return self._segment_limit

    def _segment_path(self, index: int) -> str:
        return os.path.join(self._root, f"{self._topic}-{index:05d}.jsonl")

    def _anchor_path(self, index: int) -> str:
        return self._segment_path(index) + ANCHOR_SUFFIX

    def segment_path(self, index: int) -> str:
        """返回某段的文件路径（段可能尚不存在）。"""

        return self._segment_path(index)

    def has_segment(self, index: int) -> bool:
        """某段的数据文件是否存在。"""

        return os.path.isfile(self._segment_path(index))

    def _scan_segments(self) -> list[tuple[int, int]]:
        """扫描磁盘上实际存在的段，返回 (段号, 有效行数) 升序列表。"""

        found: list[tuple[int, int]] = []
        prefix = f"{self._topic}-"
        try:
            names = os.listdir(self._root)
        except OSError as error:
            raise StorageError(f"扫描流水目录失败: {error}", component="store") from error
        for name in names:
            if not (name.startswith(prefix) and name.endswith(".jsonl")):
                continue
            middle = name[len(prefix) : -len(".jsonl")]
            if not middle.isdigit():
                continue
            index = int(middle)
            path = os.path.join(self._root, name)
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    size = sum(1 for line in handle if line.strip())
            except OSError as error:
                raise StorageError(f"读取流水 {path} 失败: {error}", component="store") from error
            found.append((index, size))
        found.sort()
        return found

    def _existing_sizes(self) -> list[tuple[int, int]]:
        """扫描磁盘上真实存在的段文件，返回 (段号, 有效行数) 升序列表。

        段号中间的跳号（文件不存在）不补位，避免把「下一个待写段号」误当成
        空段实体。
        """

        return self._scan_segments()

    def is_sealed(self, index: int) -> bool:
        """段是否已封存：满段或已有锚点即视为封存。"""

        return self.anchor_exists(index) or self._segment_size(index) >= self._segment_limit

    def next_writable_segment(self, index: int | None = None) -> int:
        """返回从 ``index`` 起第一个可追加的段号；满段/锚点段一律跳过。"""

        target = self._segment if index is None else index
        while self.is_sealed(target):
            target += 1
        return target

    def append(self, record: Any) -> str:
        """追加一条记录，需要时自动滚动到下一段，返回写入的段路径。"""

        with self._lock:
            return self.append_to(self._segment, record)

    def append_to(self, index: int, record: Any) -> str:
        """向链头方向第一个可写段追加记录；满段与封存段会被自动跳过。"""

        with self._lock:
            target = self.next_writable_segment(max(index, self._segment))
            path = self._segment_path(target)
            try:
                with open(path, "a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record, ensure_ascii=False) + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
            except OSError as error:
                raise StorageError(f"追加流水失败: {error}", component="store") from error
            self._bump_size(target, 1)
            self._count += 1
            self._segment = target
            return path

    def _segment_size(self, index: int) -> int:
        sizes = dict(self._sizes)
        return sizes.get(index, 0)

    def _bump_size(self, index: int, delta: int) -> None:
        sizes = dict(self._sizes)
        if index not in sizes:
            sizes[index] = 0
            self._sizes = sorted((idx, size) for idx, size in sizes.items())
        sizes = dict(self._sizes)
        sizes[index] = sizes.get(index, 0) + delta
        self._sizes = sorted(sizes.items())

    def seal_active(self) -> int:
        """封存当前活动段并把活动段号推进到下一段（空段也允许封存）。"""

        with self._lock:
            sealed = self._segment
            self._segment = sealed + 1
            return sealed

    def refresh_active(self) -> int:
        """按磁盘段文件重算活动段号（恢复/封存后校正内部状态）。"""

        with self._lock:
            self._sizes = self._existing_sizes()
            self._count = sum(size for _index, size in self._sizes)
            self._segment = self._sizes[-1][0] if self._sizes else 0
            return self._segment

    def write_anchor(self, index: int, payload: dict[str, Any]) -> str:
        """原子写入某段的封存锚点；锚点只允许写一次。"""

        target = self._anchor_path(index)
        with self._lock:
            if os.path.isfile(target):
                raise StorageError(f"段 {index} 的锚点已存在，不可覆盖", component="store")
            directory = self._root
            tmp_name = ""
            try:
                handle = tempfile.NamedTemporaryFile(
                    "w",
                    encoding="utf-8",
                    dir=directory,
                    prefix=f".anchor-{index:05d}.",
                    suffix=".tmp",
                    delete=False,
                )
                tmp_name = handle.name
                with handle:
                    json.dump(payload, handle, ensure_ascii=False, indent=2)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp_name, target)
                self._fsync_dir()
            except OSError as error:
                if tmp_name and os.path.exists(tmp_name):
                    try:
                        os.remove(tmp_name)
                    except OSError:
                        pass
                raise StorageError(f"写入封存锚点失败: {error}", component="store") from error
            return target

    def anchor_exists(self, index: int) -> bool:
        """某段是否已有封存锚点。"""

        return os.path.isfile(self._anchor_path(index))

    def read_anchor(self, index: int) -> dict[str, Any] | None:
        """读取某段锚点，不存在返回 ``None``。"""

        path = self._anchor_path(index)
        if not os.path.isfile(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except (OSError, json.JSONDecodeError) as error:
            raise StorageError(f"读取锚点 {path} 失败: {error}", component="store") from error

    def _fsync_dir(self) -> None:
        try:
            dir_fd = os.open(self._root, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(dir_fd)
        except OSError:
            pass
        finally:
            os.close(dir_fd)

    def recover_tail(self, index: int | None = None) -> int:
        """恢复活动段末尾：丢掉最后一个不完整行，返回丢弃的字节数。

        只允许处理最新的、没有锚点的段；封存段末尾的损坏按篡改处理，绝不删改。
        """

        with self._lock:
            target = self._segment if index is None else index
            path = self._segment_path(target)
            if not os.path.isfile(path) or self.anchor_exists(target):
                return 0
            try:
                with open(path, "rb+") as handle:
                    handle.seek(0, os.SEEK_END)
                    size = handle.tell()
                    if size == 0:
                        return 0
                    # 从末尾向前找最后一个换行；换行之后若还有字节就是半行。
                    probe = min(size, 1 << 20)
                    handle.seek(size - probe)
                    tail = handle.read()
                    last_nl = tail.rfind(b"\n")
                    if last_nl < 0:
                        new_size = 0
                    else:
                        new_size = size - probe + last_nl + 1
                    if new_size == size:
                        return 0
                    handle.truncate(new_size)
                    handle.flush()
                    os.fsync(handle.fileno())
                    dropped = size - new_size
            except OSError as error:
                raise StorageError(f"恢复流水段失败: {error}", component="store") from error
            self._sizes = self._existing_sizes()
            if self._sizes:
                self._segment = self._sizes[-1][0]
                self._count = sum(size for _idx, size in self._sizes)
            return dropped

    def segments(self) -> list[str]:
        """返回已存在的段文件路径（按段号升序，空洞补空路径位由 segment_paths 决定）。"""

        return [self._segment_path(index) for index, _size in self._sizes]

    def segment_paths(self) -> list[str]:
        """返回全部段路径（含中间空洞），按段号升序。"""

        return self.segments()

    def segment_indices(self) -> list[int]:
        """返回全部段号（含中间空洞）。"""

        return [index for index, _size in self._sizes]

    def segment_sizes(self) -> list[int]:
        """返回各段有效行数。"""

        return [size for _index, size in self._sizes]

    def read_segment(self, index: int) -> list[dict]:
        """读取指定段。"""

        path = self._segment_path(index)
        if not os.path.isfile(path):
            return []
        return self._read_file(path)

    def iter_segment_raw(self, index: int) -> Iterator[bytes]:
        """逐行产出某段原始字节，供大段流式校验。"""

        path = self._segment_path(index)
        if not os.path.isfile(path):
            return
        try:
            with open(path, "rb") as handle:
                for line in handle:
                    line = line.rstrip(b"\r\n")
                    if line.strip():
                        yield line
        except OSError as error:
            raise StorageError(f"读取流水 {path} 失败: {error}", component="store") from error

    def read_all(self) -> list[dict]:
        """按段号顺序读取全部记录。"""

        records: list[dict] = []
        for index, _size in self._sizes:
            records.extend(self.read_segment(index))
        return records

    def count(self) -> int:
        """返回累计写入条数。"""

        with self._lock:
            return self._count

    def active_segment(self) -> int:
        """返回当前正在写入的段号。"""

        with self._lock:
            return self._segment

    def _read_file(self, path: str) -> list[dict]:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return [json.loads(line) for line in handle if line.strip()]
        except (OSError, json.JSONDecodeError) as error:
            raise StorageError(f"读取流水 {path} 失败: {error}", component="store") from error
