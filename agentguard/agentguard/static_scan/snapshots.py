"""服务端私有设备快照暂存，不接受客户端指定本地路径。"""

import os
import shutil
import tempfile
from pathlib import Path


def snapshot_base(repository) -> Path:
    return Path(repository.path).absolute().parent / "device-snapshots"


def stage_snapshot(repository, scan_id: str, files: list) -> str:
    base = snapshot_base(repository)
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix=scan_id + "-", dir=base))
    try:
        for item in files:
            target = root / item["path"]
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with target.open("x", encoding="utf-8") as handle:
                os.chmod(target, 0o600)
                handle.write(item["content"])
    except Exception:
        shutil.rmtree(root)
        raise
    return str(root)


def cleanup_snapshot(repository, record) -> None:
    if not record or not record.device_id or not record.source_path:
        return
    path = Path(record.source_path)
    base = snapshot_base(repository)
    if path.parent == base and path.name.startswith(record.scan_id + "-") and not path.is_symlink():
        shutil.rmtree(path, ignore_errors=True)
