"""文件索引、Skill 归属与稳定身份。

FileIndex 只保存元数据与内容指纹；文件正文在解析阶段按需读取并校验
快照摘要，避免一次性把整个目录读进内存，也能发现校验后被替换的文件。
"""

import posixpath
from dataclasses import dataclass, field

from .models import stable_asset_id

# 默认排除目录（方案 §7）：依赖仍从清单解析，不宣称已审计其全部源码。
EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", ".env",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox",
    "dist", "build", ".next", ".nuxt", "target", ".cache", ".idea", ".vscode",
    "site-packages", ".terraform",
}

# 二进制/生成物直接跳过，避免无意义解析。
SKIPPED_SUFFIXES = (
    ".pyc", ".pyo", ".so", ".dylib", ".dll", ".exe", ".bin", ".whl", ".egg",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".tar",
    ".gz", ".tgz", ".bz2", ".xz", ".7z", ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".mov", ".avi", ".sqlite", ".db", ".class", ".jar", ".o",
    ".a", ".lockb", ".DS_Store",
)

LOCKFILE_NAMES = {
    "poetry.lock", "pipfile.lock", "package-lock.json", "yarn.lock",
    "pnpm-lock.yaml", "uv.lock", "cargo.lock", "composer.lock", "gemfile.lock",
}

LANGUAGE_BY_CATEGORY = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "javascript",
    "markdown": "markdown",
    "skill_md": "markdown",
    "json": "json",
    "yaml": "yaml",
    "toml": "toml",
    "compose": "yaml",
    "dockerfile": "dockerfile",
    "requirements": "text",
    "lockfile": "text",
    "env": "text",
    "shell": "shell",
    "ini": "ini",
    "text": "text",
    "other": "other",
}


def classify(rel_path: str) -> str:
    """按文件名与后缀确定解析类别；不做内容嗅探。"""
    name = posixpath.basename(rel_path).lower()
    lower_path = rel_path.lower().replace("\\", "/")
    suffix = posixpath.splitext(name)[1]

    if name == "skill.md":
        return "skill_md"
    if name in LOCKFILE_NAMES or name.endswith(".lock"):
        return "lockfile"
    if name.startswith("dockerfile") or name.endswith(".dockerfile"):
        return "dockerfile"
    if name.startswith("docker-compose") or name.startswith("compose."):
        if suffix in (".yml", ".yaml"):
            return "compose"
    if name.startswith("requirements") and suffix == ".txt":
        return "requirements"
    if "/requirements/" in f"/{lower_path}" and suffix == ".txt":
        return "requirements"
    if name.startswith("constraints") and suffix == ".txt":
        return "requirements"
    if name.startswith(".env") or name.endswith(".env") or ".env." in name:
        return "env"
    if suffix == ".py":
        return "python"
    if suffix in (".js", ".mjs", ".cjs", ".jsx"):
        return "javascript"
    if suffix in (".ts", ".tsx"):
        return "typescript"
    if suffix == ".md":
        return "markdown"
    if suffix == ".json":
        return "json"
    if suffix in (".yml", ".yaml"):
        return "yaml"
    if suffix == ".toml":
        return "toml"
    if suffix in (".sh", ".bash", ".zsh"):
        return "shell"
    if suffix in (".ini", ".cfg", ".conf"):
        return "ini"
    if suffix == ".txt":
        return "text"
    return "other"


CONFIG_CATEGORIES = {
    "compose", "dockerfile", "requirements", "lockfile", "env", "json",
    "yaml", "toml", "ini",
}

TEXT_CATEGORIES = {
    "python", "javascript", "typescript", "markdown", "skill_md", "json",
    "yaml", "toml", "compose", "dockerfile", "requirements", "lockfile",
    "env", "shell", "ini", "text",
}


@dataclass
class FileEntry:
    path: str  # 相对项目根的 POSIX 路径
    size: int
    digest: str
    category: str
    language: str = ""
    skill_dir: str = ""  # 最近祖先 SKILL.md 所在目录，没有则为空
    mtime_ns: int = 0
    parse_skip: str = ""  # file_too_large / unsupported_binary / ...
    read_error: str = ""

    def as_dict(self) -> dict:
        return vars(self)


@dataclass
class FileIndex:
    """快照文件索引：稳定顺序、来源可追溯、排除策略显式记录。"""

    root: str = ""
    project_root: str = ""
    files: list = field(default_factory=list)
    skipped: list = field(default_factory=list)  # {path, reason}
    unsafe: list = field(default_factory=list)  # 越界链接、设备文件等
    limit_hits: list = field(default_factory=list)
    truncated: bool = False
    total_bytes: int = 0
    excluded_dirs: tuple = tuple(sorted(EXCLUDED_DIRS))
    _by_path: dict = field(default_factory=dict, repr=False)
    _skill_dirs: dict = field(default_factory=dict, repr=False)

    def add(self, entry: FileEntry) -> None:
        self.files.append(entry)

    def finalize(self) -> None:
        self.files.sort(key=lambda item: item.path)
        self._by_path = {entry.path: entry for entry in self.files}
        self._skill_dirs = {
            posixpath.dirname(entry.path): entry.path
            for entry in self.files
            if entry.category == "skill_md"
        }
        for entry in self.files:
            entry.skill_dir = self.owner(entry.path) or ""

    def owner(self, rel_path: str) -> str | None:
        """Skill 文件归属于最近祖先 SKILL.md；嵌套 Skill 单独分区。"""
        current = posixpath.dirname(rel_path)
        while True:
            if current in self._skill_dirs:
                return current
            if current in ("", "."):
                return None
            parent = posixpath.dirname(current)
            if parent == current:
                return None
            current = parent

    def get(self, rel_path: str) -> FileEntry | None:
        return self._by_path.get(rel_path)

    def of_categories(self, *categories: str) -> list:
        wanted = set(categories)
        return [entry for entry in self.files if entry.category in wanted]

    def skill_markdowns(self) -> dict:
        """skill_dir -> SKILL.md 相对路径。"""
        return dict(self._skill_dirs)

    def category_counts(self) -> dict:
        counts: dict = {}
        for entry in self.files:
            counts[entry.category] = counts.get(entry.category, 0) + 1
        return counts

    def language_counts(self) -> dict:
        counts: dict = {}
        for entry in self.files:
            if entry.parse_skip:
                continue
            counts[entry.language or "other"] = counts.get(entry.language or "other", 0) + 1
        return counts

    def snapshot_signature(self) -> str:
        from .models import digest_text

        payload = "\n".join(f"{entry.path}|{entry.digest}" for entry in self.files)
        return digest_text(payload, 32)


def asset_id(project_id: str, kind: str, logical_key: str) -> str:
    return stable_asset_id(project_id, kind, logical_key)
