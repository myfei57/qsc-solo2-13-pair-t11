"""安全联动适配器。

广播与门禁是高温区人员安全的外部执行端：组件不直接驱动硬件，而是把联动指令按
平台「先落盘、后动作」的口径写入持久化层——广播指令追加到 ``safety/broadcast``
流水（PA 网关按序消费），门禁模式写入 ``safety/access/{zone}`` 记录（门禁控制器
回读执行）。每一次联动都有可校验的落盘凭证，事后审计能把报警与联动逐条对上。
"""

from __future__ import annotations

from typing import Any, Mapping

from ..errors import ValidationError
from ..runtime import RuntimeContext

BROADCAST_STREAM = "safety/broadcast"
ACCESS_MODES = ("normal", "lockdown", "evacuate")
BROADCAST_LEVELS = ("info", "warning", "emergency")


class DurableBroadcast:
    """广播联动：播报指令追加到持久流水，流水序号即回执。"""

    def __init__(self, ctx: RuntimeContext) -> None:
        self._ctx = ctx

    def announce(self, message: str, *, zone: str, level: str, actor: str) -> Mapping[str, Any]:
        if not message:
            raise ValidationError("广播内容不能为空")
        if level not in BROADCAST_LEVELS:
            raise ValidationError(
                "非法的广播级别", details={"level": level, "allowed": list(BROADCAST_LEVELS)}
            )
        entry = self._ctx.store.append(
            BROADCAST_STREAM,
            {
                "message": message,
                "zone": zone,
                "level": level,
                "actor": actor,
                "at": self._ctx.clock.timestamp_iso(),
            },
        )
        return {"stream": BROADCAST_STREAM, "seq": entry.seq, "zone": zone, "level": level}


class DurableAccessControl:
    """门禁联动：区域门禁模式落盘为可回读校验的记录。"""

    def __init__(self, ctx: RuntimeContext) -> None:
        self._ctx = ctx

    def set_mode(self, zone: str, mode: str, *, reason: str, actor: str) -> Mapping[str, Any]:
        if mode not in ACCESS_MODES:
            raise ValidationError(
                "非法的门禁模式", details={"mode": mode, "allowed": list(ACCESS_MODES)}
            )
        record = self._ctx.store.commit_intent(
            self._ctx.key("safety", "access", zone),
            {
                "zone": zone,
                "mode": mode,
                "reason": reason,
                "actor": actor,
                "at": self._ctx.clock.timestamp_iso(),
            },
        )
        return {"key": record.key, "version": record.version, "zone": zone, "mode": mode}

    def modes(self) -> dict[str, str]:
        prefix = self._ctx.key("safety", "access")
        result: dict[str, str] = {}
        for key in self._ctx.store.list_keys(prefix):
            record = self._ctx.store.get(key)
            if record is not None:
                result[key[len(prefix) + 1 :]] = str(record.payload.get("mode", "normal"))
        return result


__all__ = ["DurableBroadcast", "DurableAccessControl", "BROADCAST_STREAM", "ACCESS_MODES", "BROADCAST_LEVELS"]
