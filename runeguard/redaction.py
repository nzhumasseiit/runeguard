import re
from collections.abc import Mapping, Sequence


SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
    re.compile(r"AIza[0-9A-Za-z_-]{30,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"(?:rk|sk|pk)_(?:live|test)_[0-9A-Za-z]{16,}"),
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
        re.MULTILINE,
    ),
    re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9_-]{48,}(?![A-Za-z0-9])"),
)


def redact_text(value: str) -> str:
    redacted = value
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(lambda match: _redact_match(match.group(0)), redacted)
    return redacted


def redact_value(value):
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return {key: redact_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return tuple(redact_value(item) for item in value)
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return [redact_value(item) for item in value]
    return value


def preview_secret(value: str) -> str:
    return _redact_match(value)


def _redact_match(value: str) -> str:
    if "PRIVATE KEY" in value:
        return "[REDACTED PRIVATE KEY]"

    prefix_length = 3
    if value.startswith(("sk-ant-", "sk-live-", "sk-test-", "pk-live-", "pk-test-")):
        prefix_length = min(8, len(value))
    elif value.startswith(("ghp_", "gho_", "ghu_", "ghs_", "ghr_")):
        prefix_length = 4
    elif value.startswith(("AKIA", "ASIA", "AIza")):
        prefix_length = 4

    suffix = value[-4:] if len(value) > 8 else ""
    return f"{value[:prefix_length]}...{suffix}" if suffix else "[REDACTED]"
