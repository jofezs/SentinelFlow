from sentinelflow_dockerfile_scanner.parser import Instruction, final_stage, parse


def test_parses_instructions_with_line_numbers() -> None:
    content = "# comment\nFROM python:3.12\n\nrun pip install x\nUSER app\n"
    assert parse(content) == [
        Instruction(2, "FROM", "python:3.12"),
        Instruction(4, "RUN", "pip install x"),
        Instruction(5, "USER", "app"),
    ]


def test_joins_line_continuations_and_skips_inner_comments() -> None:
    content = "FROM alpine\nRUN apk add \\\n    # a comment\n    curl \\\n    git\n"
    instructions = parse(content)
    assert instructions[1] == Instruction(2, "RUN", "apk add curl git")


def test_trailing_continuation_is_flushed() -> None:
    assert parse("FROM alpine\nRUN echo hi \\")[-1] == Instruction(2, "RUN", "echo hi")


def test_final_stage_starts_at_last_from() -> None:
    instructions = parse("FROM golang AS build\nUSER root\nFROM alpine\nCMD ['app']\n")
    assert [i.keyword for i in final_stage(instructions)] == ["FROM", "CMD"]


def test_empty_input() -> None:
    assert parse("") == []
    assert final_stage([]) == []
