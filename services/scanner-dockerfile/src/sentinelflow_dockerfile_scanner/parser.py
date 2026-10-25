"""Minimal Dockerfile parser: enough structure for security rules.

Handles comments, blank lines, and backslash line continuations. Heredocs and
parser directives are not interpreted (they are treated as plain text).
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Instruction:
    line: int  # 1-based line where the instruction starts
    keyword: str  # upper-cased, e.g. "RUN"
    args: str


def parse(content: str) -> list[Instruction]:
    instructions: list[Instruction] = []
    parts: list[str] = []
    start: int | None = None

    def flush() -> None:
        nonlocal parts, start
        joined = " ".join(p for p in parts if p)
        if joined and start is not None:
            keyword, _, args = joined.partition(" ")
            instructions.append(Instruction(start, keyword.upper(), args.strip()))
        parts, start = [], None

    for lineno, raw in enumerate(content.splitlines(), start=1):
        stripped = raw.strip()
        if stripped.startswith("#") or (not stripped and start is None):
            continue  # comments are dropped, even inside a continuation
        if start is None:
            start = lineno
        if stripped.endswith("\\"):
            parts.append(stripped[:-1].strip())
            continue
        parts.append(stripped)
        flush()
    flush()
    return instructions


def final_stage(instructions: list[Instruction]) -> list[Instruction]:
    """Instructions from the last FROM onward: the stage that becomes the image."""
    last_from = max(
        (i for i, ins in enumerate(instructions) if ins.keyword == "FROM"),
        default=0,
    )
    return instructions[last_from:]
