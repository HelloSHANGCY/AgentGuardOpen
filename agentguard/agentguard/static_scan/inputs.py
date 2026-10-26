"""授权根、目录快照与限额。

安全边界（方案 §7）：
- 只接受管理员登记的 source_id，不接受任意宿主机路径；
- 拒绝设备文件、FIFO、越界符号链接；不跟随目录符号链接；
- 逐文件记录摘要，读取时用 O_NOFOLLOW + fstat 复核，发现变化标 PARTIAL；
- 达到总文件数/总大小/目录深度限额后停止并记录覆盖缺口。
"""

import hashlib
import os
import stat
from dataclasses import asdict, dataclass

from .inventory import EXCLUDED_DIRS, LANGUAGE_BY_CATEGORY, SKIPPED_SUFFIXES, FileEntry, FileIndex, classify

CHUNK = 64 * 1024
BINARY_SNIFF_BYTES = 8192


@dataclass
class Limits:
    """默认限额（方案 §7 建议值，属于配置值而非已测性能）。"""

    max_files: int = 20000
    max_total_bytes: int = 200 * 1024 * 1024
    max_file_parse_bytes: int = 2 * 1024 * 1024
    max_depth: int = 32
    parse_timeout_seconds: float = 5.0
    scan_timeout_seconds: float = 600.0
    zip_max_bytes: int = 200 * 1024 * 1024
    zip_max_ratio: int = 100
    max_yaml_nodes: int = 10000
    max_yaml_depth: int = 32
    max_yaml_aliases: int = 200
    max_decode_layers: int = 2
    max_decoded_bytes: int = 256 * 1024
    max_flow_depth: int = 3
    max_paths_per_entry: int = 200
    max_calls_per_function: int = 50
    max_graph_nodes: int = 500

    def as_dict(self) -> dict:
        return asdict(self)


class InputError(Exception):
    """输入隔离相关错误（授权、限额、路径越界）。"""


def authorized_source(source_id: str, sources: dict) -> str:
    """source_id -> 管理员登记的只读根目录；未登记一律拒绝。"""
    if source_id not in (sources or {}):
        raise InputError(f"source_id not registered: {source_id!r}")
    root = os.path.realpath(str(sources[source_id]))
    if not os.path.isdir(root):
        raise InputError(f"source root is not a directory: {source_id!r}")
    return root


def ensure_within(root: str, path: str) -> str:
    """解析真实路径并确认位于授权根内（防 ../ 与符号链接逃逸）。"""
    real = os.path.realpath(path)
    base = os.path.realpath(root)
    if real != base and not real.startswith(base + os.sep):
        raise InputError(f"path escapes authorized root: {path!r}")
    return real


def effective_roots(settings) -> tuple:
    """授权根白名单：显式 AG_STATIC_ROOTS 优先，否则回退为已登记 sources 的路径。"""
    roots = getattr(settings, "static_roots", ()) or ()
    if not roots:
        roots = tuple((getattr(settings, "static_sources", {}) or {}).values())
    resolved = []
    for root in roots:
        real = os.path.realpath(str(root))
        if real not in resolved:
            resolved.append(real)
    return tuple(resolved)


def is_within_roots(path: str, roots) -> bool:
    """路径（解析符号链接后）是否位于任一授权根内。"""
    real = os.path.realpath(str(path))
    for root in roots or ():
        base = os.path.realpath(str(root))
        if real == base or real.startswith(base + os.sep):
            return True
    return False


def resolve_scan_root(path: str, roots) -> str:
    """把请求提交的路径解析为白名单内的只读根；越界/不存在/非目录一律拒绝。"""
    if not str(path or "").strip():
        raise InputError("path is empty")
    candidate = os.path.realpath(str(path))
    if not os.path.isdir(candidate):
        raise InputError(f"path is not a directory: {path!r}")
    if not is_within_roots(candidate, roots):
        raise InputError(f"path is outside authorized roots: {path!r}")
    return candidate


def path_source_id(path: str) -> str:
    """自定义路径的稳定 source_id：同一真实路径重复扫描归入同一来源。"""
    digest = hashlib.sha256(os.path.realpath(str(path)).encode("utf-8")).hexdigest()
    return f"path-{digest[:12]}"


def _digest_file(path: str) -> tuple:
    hasher = hashlib.sha256()
    size = 0
    binary = False
    with open(path, "rb") as handle:
        first = True
        while True:
            chunk = handle.read(CHUNK)
            if not chunk:
                break
            if first:
                binary = b"\x00" in chunk[:BINARY_SNIFF_BYTES]
                first = False
            hasher.update(chunk)
            size += len(chunk)
    return "sha256:" + hasher.hexdigest()[:32], size, binary


def snapshot_root(root: str, limits: Limits = None) -> FileIndex:
    """只读遍历授权根，生成带内容摘要的文件索引。"""
    limits = limits or Limits()
    index = FileIndex(root=root, project_root=root)

    def walk(directory: str, rel_dir: str, depth: int) -> None:
        if depth > limits.max_depth:
            index.truncated = True
            index.limit_hits.append({"limit": "max_depth", "path": rel_dir or "."})
            return
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            index.skipped.append({"path": rel_dir or ".", "reason": f"unreadable_dir:{exc.__class__.__name__}"})
            return

        for item in entries:
            rel_path = f"{rel_dir}/{item.name}" if rel_dir else item.name
            if item.is_symlink():
                # 不跟随任何符号链接；越界与否都记录为跳过，避免 TOCTOU。
                index.unsafe.append({"path": rel_path, "reason": "symlink"})
                continue
            try:
                if item.is_dir(follow_symlinks=False):
                    if item.name in EXCLUDED_DIRS:
                        index.skipped.append({"path": rel_path, "reason": "excluded_dir"})
                        continue
                    walk(item.path, rel_path, depth + 1)
                    continue
                if not item.is_file(follow_symlinks=False):
                    # 设备文件、FIFO、socket 等一律拒绝。
                    index.unsafe.append({"path": rel_path, "reason": "not_regular_file"})
                    continue
            except OSError as exc:
                index.skipped.append({"path": rel_path, "reason": f"stat_failed:{exc.__class__.__name__}"})
                continue

            name = item.name.lower()
            suffix = os.path.splitext(name)[1]
            if suffix in SKIPPED_SUFFIXES:
                index.skipped.append({"path": rel_path, "reason": "binary_suffix"})
                continue
            if len(index.files) >= limits.max_files:
                index.truncated = True
                if not any(hit["limit"] == "max_files" for hit in index.limit_hits):
                    index.limit_hits.append({"limit": "max_files", "path": rel_path})
                return

            try:
                digest, size, binary = _digest_file(item.path)
            except OSError as exc:
                index.skipped.append({"path": rel_path, "reason": f"read_failed:{exc.__class__.__name__}"})
                continue

            if index.total_bytes + size > limits.max_total_bytes:
                index.truncated = True
                if not any(hit["limit"] == "max_total_bytes" for hit in index.limit_hits):
                    index.limit_hits.append({"limit": "max_total_bytes", "path": rel_path})
                return

            category = classify(rel_path)
            parse_skip = ""
            if size > limits.max_file_parse_bytes:
                parse_skip = "file_too_large"
            elif binary:
                parse_skip = "unsupported_binary"
            elif category == "other" and not parse_skip:
                # 未知后缀保留元数据，不尝试解析。
                parse_skip = "unsupported_category"

            entry = FileEntry(
                path=rel_path,
                size=size,
                digest=digest,
                category=category,
                language=LANGUAGE_BY_CATEGORY.get(category, "other"),
                mtime_ns=item.stat(follow_symlinks=False).st_mtime_ns,
                parse_skip=parse_skip,
            )
            index.add(entry)
            index.total_bytes += size

    index.total_bytes = 0
    walk(root, "", 0)
    index.limits = limits.as_dict()
    index.finalize()
    return index


def read_verified_text(root: str, entry: FileEntry, limits: Limits = None) -> str | None:
    """读取文件并用快照摘要校验；发现替换/变化时重试一次，仍失败返回 None。"""
    limits = limits or Limits()
    real = ensure_within(root, os.path.join(root, entry.path))
    for attempt in range(2):
        try:
            fd = os.open(real, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError as exc:
            entry.read_error = f"open_failed:{exc.__class__.__name__}"
            return None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                entry.read_error = "not_regular_file"
                return None
            chunks = []
            total = 0
            while total <= limits.max_file_parse_bytes:
                chunk = os.read(fd, CHUNK)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
        finally:
            os.close(fd)
        raw = b"".join(chunks)
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()[:32]
        if digest == entry.digest:
            return raw.decode("utf-8", "replace")
        if attempt == 1:
            entry.read_error = "digest_changed"
            return None
    return None
