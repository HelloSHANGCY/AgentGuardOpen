"""Bounded shell structure for feature extraction and data-flow evidence.

This is a deliberately restricted parser, not a shell evaluator. Quotes, comments,
substitutions and heredoc bodies never become top-level command separators.
Unsupported constructs explicitly lower coverage; no variable expansion occurs.
"""

import re
import shlex
from dataclasses import dataclass, field

MAX_CHARS = 32768
MAX_COMMANDS = 128
MAX_DEPTH = 4
OPERATORS = ("&&", "||", "|&", ">>", "<<", ">&", "<&", ";", "|", "&", ">", "<", "\n")
REDIRECTS = {">", ">>", "<", ">&", "<&"}


@dataclass
class Command:
    words: list[str]
    redirects: list[tuple[str, str]] = field(default_factory=list)
    before: str = ""
    certain: bool = True


@dataclass
class Structure:
    commands: list[Command] = field(default_factory=list)
    complete: bool = True
    reasons: list[str] = field(default_factory=list)


def parse(text: str) -> Structure:
    result = Structure()

    def incomplete(reason):
        result.complete = False
        if reason not in result.reasons:
            result.reasons.append(reason)

    if len(text) > MAX_CHARS:
        incomplete("length_limit")
        text = text[:MAX_CHARS]
    # Skip heredoc bodies, including examples containing shell operators.
    lines, pending, kept = text.splitlines(keepends=True), [], []
    for line in lines:
        if pending:
            delimiter, tabs = pending[0]
            if (line.lstrip("\t") if tabs else line).rstrip("\r\n") == delimiter:
                pending.pop(0)
            continue
        heredocs = list(re.finditer(r"<<(-)?\s*(['\"]?)([\w.-]+)\2", line))
        if heredocs:
            incomplete("heredoc")
            pending.extend((m[3], bool(m[1])) for m in heredocs)
            line = re.sub(r"<<-?\s*(['\"]?)[\w.-]+\1", "", line)
        kept.append(line)
    if pending:
        incomplete("unterminated_heredoc")
    text = "".join(kept)
    words, redirects, buf = [], [], []
    quote, escaped, substitution, backtick = "", False, 0, False
    before, redirect = "", ""
    certain = result.complete

    def word():
        nonlocal redirect
        if not buf:
            return
        raw = "".join(buf)
        buf.clear()
        try:
            values = shlex.split(raw, comments=False)
        except ValueError:
            values = [raw]
            incomplete("quoting")
        if redirect:
            redirects.append((redirect, values[0] if values else ""))
            redirect = ""
        else:
            words.extend(values)

    def command(op):
        nonlocal words, redirects, before, certain
        word()
        if words or redirects:
            result.commands.append(Command(words, redirects, before, certain))
        words, redirects, before = [], [], op
        certain = result.complete

    index = 0
    while index < len(text):
        char = text[index]
        if escaped:
            buf.append(char)
            escaped = False
        elif char == "\\" and quote != "'":
            buf.append(char)
            escaped = True
        elif char == "'" and not quote and not substitution and not backtick:
            quote = char
            buf.append(char)
        elif quote == "'":
            buf.append(char)
            if char == "'":
                quote = ""
        elif char == '"' and not substitution and not backtick:
            quote = "" if quote else char
            buf.append(char)
        elif text.startswith("$(", index):
            incomplete("substitution")
            certain = False
            substitution += 1
            buf.append("$(")
            index += 1
        elif substitution:
            buf.append(char)
            if char == "(":
                substitution += 1
            elif char == ")":
                substitution -= 1
        elif char == "`":
            incomplete("substitution")
            certain = False
            backtick = not backtick
            buf.append(char)
        elif backtick or quote:
            buf.append(char)
        elif char == "#" and not buf:
            end = text.find("\n", index)
            index = len(text) if end < 0 else end - 1
        elif char in "(){}":
            incomplete("control_structure")
            certain = False
            buf.append(char)
        else:
            op = next((op for op in OPERATORS if text.startswith(op, index)), "")
            if op:
                if op in REDIRECTS:
                    # A numeric fd immediately before a redirect is not an argument.
                    if buf and "".join(buf).isdigit():
                        buf.clear()
                    word()
                    redirect = op
                else:
                    if op in ("&", "|&", "<<"):
                        incomplete("unsupported_operator")
                    command(op)
                index += len(op) - 1
            elif char.isspace():
                word()
            else:
                buf.append(char)
        index += 1
        if len(result.commands) >= MAX_COMMANDS:
            incomplete("command_limit")
            break
    command("")
    if quote or escaped or substitution or backtick or redirect:
        incomplete("incomplete_syntax")
    if any(cmd.words and cmd.words[0] in {"if", "then", "for", "while", "case", "fi", "done", "else"}
           for cmd in result.commands):
        incomplete("control_structure")
    if not result.complete:
        for cmd in result.commands:
            cmd.certain = False
    return result
