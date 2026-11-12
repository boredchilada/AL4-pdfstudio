"""Service settings helpers. Pure Python, no AssemblyLine imports.

A `config` of None (ServiceBase types it Optional) is treated as empty.

Service-wide `config` values and per-submission parameters are read through these functions so a
bad value never stops `start()`: a wrong type falls back to the default, an out-of-range number is
clamped, and one warning names the setting and the value used. Values of secret-looking settings
are never logged.

`config_fingerprint()` is what a service returns from `get_tool_version()`. AL's result cache key
contains the submission parameters and the tool version but not `config`, so without it a changed
setting would keep serving results made under the old one.
"""

import hashlib
import json
import math
import re
from collections.abc import Mapping
from typing import Any

_SECRET_KEY = re.compile(r"(?i)(api[_-]?key|token|password|passwd|secret|auth|credential)")
_TRUE = {"true", "1"}
_FALSE = {"false", "0"}


def _warn(log: Any, name: str, problem: str, used: Any) -> None:
    if log is None:
        return
    shown = "<hidden>" if _SECRET_KEY.search(name) else repr(used)
    log.warning("Setting %s %s; using %s", name, problem, shown)


def _to_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if math.isfinite(value) and value == int(value) else None
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def _to_float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        number = float(value)
    elif isinstance(value, str):
        try:
            number = float(value.strip())
        except ValueError:
            return None
    else:
        return None
    return number if math.isfinite(number) else None


def _to_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text in _TRUE:
            return True
        if text in _FALSE:
            return False
    return None


def _clamp(log: Any, name: str, number: Any, minimum: Any, maximum: Any) -> Any:
    clamped = min(max(number, minimum), maximum)
    if clamped != number:
        _warn(log, name, f"value {number!r} is outside {minimum}..{maximum}", clamped)
    return clamped


def config_int(config: Mapping[str, Any] | None, name: str, default: int, minimum: int, maximum: int, log: Any) -> int:
    """Integer setting clamped to minimum..maximum; missing -> default silently, wrong type -> default."""
    if not config or name not in config:
        return default
    number = _to_int(config[name])
    if number is None:
        _warn(log, name, f"is not an integer ({type(config[name]).__name__})", default)
        return default
    return _clamp(log, name, number, minimum, maximum)


def config_float(
    config: Mapping[str, Any] | None, name: str, default: float, minimum: float, maximum: float, log: Any
) -> float:
    """Float setting clamped to minimum..maximum; missing -> default silently, wrong type -> default."""
    if not config or name not in config:
        return default
    number = _to_float(config[name])
    if number is None:
        _warn(log, name, f"is not a number ({type(config[name]).__name__})", default)
        return default
    return _clamp(log, name, number, minimum, maximum)


def config_bool(config: Mapping[str, Any] | None, name: str, default: bool, log: Any) -> bool:
    """Boolean setting; accepts a bool or the strings true/false/1/0 (any case)."""
    if not config or name not in config:
        return default
    flag = _to_bool(config[name])
    if flag is None:
        _warn(log, name, f"is not a boolean ({type(config[name]).__name__})", default)
        return default
    return flag


def config_str(config: Mapping[str, Any] | None, name: str, default: str, log: Any) -> str:
    """String setting, stripped; an empty value means the default."""
    if not config or name not in config:
        return default
    value = config[name]
    if not isinstance(value, str):
        _warn(log, name, f"is not a string ({type(value).__name__})", default)
        return default
    return value.strip() or default


def config_list(config: Mapping[str, Any] | None, name: str, default: list[str], log: Any) -> list[str]:
    """List setting from a list or a comma-separated string; items stripped, empties dropped."""
    if not config or name not in config:
        return list(default)
    value = config[name]
    if isinstance(value, str):
        items: list[Any] = value.split(",")
    elif isinstance(value, list | tuple):
        items = list(value)
    else:
        _warn(log, name, f"is not a list ({type(value).__name__})", default)
        return list(default)
    if not all(isinstance(item, str) for item in items):
        _warn(log, name, "has a non-string item", default)
        return list(default)
    return [item.strip() for item in items if item.strip()]


def param_int(request_or_value: Any, name: str, default: int, minimum: int, maximum: int) -> int:
    """Integer submission parameter. Takes a ServiceRequest (reads `name`) or a raw value."""
    number = _to_int(_param_value(request_or_value, name))
    if number is None:
        return default
    return min(max(number, minimum), maximum)


def param_bool(request_or_value: Any, name: str, default: bool) -> bool:
    """Boolean submission parameter. Takes a ServiceRequest (reads `name`) or a raw value."""
    flag = _to_bool(_param_value(request_or_value, name))
    return default if flag is None else flag


def param_choice(value: Any, choices: Any, default: str) -> str:
    """Submission parameter restricted to `choices`; anything else -> default."""
    return value if isinstance(value, str) and value in choices else default


def _param_value(request_or_value: Any, name: str) -> Any:
    getter = getattr(request_or_value, "get_param", None)
    if not callable(getter):
        return request_or_value
    try:
        return getter(name)
    except Exception:  # noqa: BLE001 - an unknown parameter must fall back to the default
        return None


def _without_secrets(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {k: _without_secrets(v) for k, v in value.items() if not _SECRET_KEY.search(str(k))}
    if isinstance(value, list | tuple):
        return [_without_secrets(v) for v in value]
    return value


def config_fingerprint(config: Mapping[str, Any] | None) -> str:
    """Stable `cfg-<12 hex>` digest of the non-secret settings, for `get_tool_version()`."""
    text = json.dumps(_without_secrets(config or {}), sort_keys=True, default=str)
    return "cfg-" + hashlib.sha256(text.encode()).hexdigest()[:12]
