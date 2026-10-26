"""Markdown / SKILL.md 结构化解析。

区分正文、代码块、引用与 HTML 注释段：文档引用攻击样例不自动判定为生效指令，
但位于代码块也不自动豁免；规则按段类型与上下文定级。
"""

import re
from dataclasses import dataclass, field

import yaml

FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n?", re.DOTALL)
FENCE_RE = re.compile(r"^\s*(```+|~~~+)")


@dataclass
class TextSegment:
    kind: str  # body / code / comment / quote / frontmatter
    text: str
    start_line: int
    end_line: int

    def as_dict(self) -> dict:
        return vars(self)


@dataclass
class MarkdownDoc:
    path: str
    frontmatter: dict = field(default_factory=dict)
    body: str = ""
    segments: list = field(default_factory=list)
    frontmatter_error: str = ""

    def all_text(self) -> str:
        return "\n".join(segment.text for segment in self.segments)

    def of_kind(self, kind: str) -> list:
        return [segment for segment in self.segments if segment.kind == kind]

    def location(self, line: int) -> tuple:
        abs_line = line if not self.frontmatter else line
        return self.path, abs_line


def parse_markdown(path: str, text: str) -> MarkdownDoc:
    doc = MarkdownDoc(path=path)
    offset = 0
    match = FRONTMATTER_RE.match(text)
    if match:
        try:
            parsed = yaml.safe_load(match.group(1)) or {}
            doc.frontmatter = parsed if isinstance(parsed, dict) else {}
        except yaml.YAMLError as exc:
            doc.frontmatter_error = f"yaml:{str(exc)[:120]}"
        offset = match.end()
        doc.segments.append(TextSegment(kind="frontmatter", text=match.group(1),
                                        start_line=1, end_line=max(1, match.group(1).count("\n") + 1)))
    doc.body = text[offset:]

    lines = doc.body.splitlines()
    base_line = text[:offset].count("\n") + (1 if offset else 0)
    buffer: list = []
    kind = "body"
    in_comment = False
    fence_marker = ""
    index = 0
    block_start = 0

    def flush(end_line: int) -> None:
        nonlocal buffer, block_start
        if buffer and any(item.strip() for item in buffer):
            doc.segments.append(TextSegment(kind=kind, text="\n".join(buffer),
                                            start_line=block_start, end_line=end_line))
        buffer = []

    while index < len(lines):
        line_no = base_line + index + 1
        line = lines[index]
        fence = FENCE_RE.match(line)

        if in_comment:
            buffer.append(line)
            if "-->" in line:
                in_comment = False
                flush(line_no)
                kind = "body"
                block_start = line_no + 1
            index += 1
            continue

        if fence and not fence_marker:
            flush(line_no - 1)
            fence_marker = fence.group(1)
            kind = "code"
            block_start = line_no
            buffer = [line]
            index += 1
            continue
        if fence and fence_marker and line.strip().startswith(fence_marker):
            buffer.append(line)
            flush(line_no)
            fence_marker = ""
            kind = "body"
            block_start = line_no + 1
            index += 1
            continue
        if fence_marker:
            buffer.append(line)
            index += 1
            continue

        if "<!--" in line:
            flush(line_no - 1)
            kind = "comment"
            block_start = line_no
            buffer = [line]
            if "-->" not in line.split("<!--", 1)[1]:
                in_comment = True
            else:
                flush(line_no)
                kind = "body"
                block_start = line_no + 1
            index += 1
            continue

        if line.lstrip().startswith(">"):
            if kind != "quote":
                flush(line_no - 1)
                kind = "quote"
                block_start = line_no
            buffer.append(line)
            index += 1
            continue

        if kind != "body":
            flush(line_no - 1)
            kind = "body"
            block_start = line_no
        buffer.append(line)
        index += 1

    flush(base_line + len(lines))
    return doc
