"""Pure payload checks shared by static analysis and offline regression tests."""

import re

BLOCKING_CODE_THREATS = {"SUBPROCESS_IMPORT", "OS_SYSTEM", "DYNAMIC_IMPORT", "EVAL_EXEC",
                         "DEFAULT_PARAM_SIDE_EFFECT", "POPEN_CALL", "SHELL_TRUE"}
DOT_RUN_RE = re.compile(r"(?:^|/)\.{3,}(?:/|$)")


def sensitive_field_names(payload) -> list[str]:
    """Return sensitive JSON field names without retaining their values."""
    if not isinstance(payload, dict):
        return []
    markers = ("SECRET", "TOKEN", "KEY", "PASSWORD", "CREDENTIAL")
    mappings = [payload, *(value for value in payload.values() if isinstance(value, dict))]
    return [key for mapping in mappings for key in mapping
            if isinstance(key, str) and any(marker in key.upper() for marker in markers)]
