"""报警联动适配层：广播与区域门禁。

报警落盘之后，组件通过这里的两个端口驱动现场设备。真实厂区里广播主机与门禁
控制器是独立接口（串口、继电器或网络协议），本包提供的是「先落盘、后执行」的
本地适配器：每条联动指令先写入 journal 再返回回执，即使将来替换成真实设备
适配器，留痕口径与组件逻辑都不用变。
"""

from __future__ import annotations

import uuid
from typing import Any, Mapping, Protocol, runtime_checkable

from ..errors import ValidationError
from ..runtime import RuntimeContext

LINKAGE_STREAM = "safety/linkage"

# 门禁联动指令集：解锁疏散通道、暂停进入授权、禁区闭锁。
ACCESS_COMMANDS = ("release_evacuation", "suspend_entry", "lockdown")


@runtime_checkable
class BroadcastPort(Protocol):
    """区域广播：把警情喊话投到指定区域（或全厂）。"""

    def announce(self, zone: str, message: str, *, alarm_id: str, kind: str) -> Mapping[str, Any]: ...


@runtime_checkable
class AccessControlPort(Protocol):
    """区域门禁：执行疏散解锁、暂停进入、禁区闭锁等联动指令。"""

    def execute(self, command: str, zone: str, *, alarm_id: str, reason: str) -> Mapping[str, Any]: ...


class _LocalLinkage:
    """本地适配器公共部分：联动指令先落盘（文档 + journal）再回报回执。"""

    def __init__(self, ctx: RuntimeContext) -> None:
        self._ctx = ctx

    def _commit(self, dispatch_id: str, receipt: Mapping[str, Any]) -> Mapping[str, Any]:
        self._ctx.store.commit_intent(self._ctx.key("safety", "linkage", dispatch_id), dict(receipt))
        self._ctx.store.append(LINKAGE_STREAM, dict(receipt))
        return receipt


class LocalBroadcast(_LocalLinkage):
    """本地广播适配器：喊话指令落盘并留回执，作为联动的权威记录。"""

    def announce(self, zone: str, message: str, *, alarm_id: str, kind: str) -> Mapping[str, Any]:
        if not message:
            raise ValidationError("广播内容不能为空", details={"zone": zone, "alarm_id": alarm_id})
        dispatch_id = "BC-" + uuid.uuid4().hex[:12]
        return self._commit(
            dispatch_id,
            {
                "dispatch_id": dispatch_id,
                "channel": "broadcast",
                "zone": zone,
                "message": message,
                "alarm_id": alarm_id,
                "kind": kind,
                "dispatched_at": self._ctx.clock.timestamp_iso(),
            },
        )


class LocalAccessControl(_LocalLinkage):
    """本地门禁适配器：联动指令落盘并留回执，作为联动的权威记录。"""

    def execute(self, command: str, zone: str, *, alarm_id: str, reason: str) -> Mapping[str, Any]:
        if command not in ACCESS_COMMANDS:
            raise ValidationError(
                "未知门禁联动指令", details={"command": command, "known": list(ACCESS_COMMANDS)}
            )
        dispatch_id = "AC-" + uuid.uuid4().hex[:12]
        return self._commit(
            dispatch_id,
            {
                "dispatch_id": dispatch_id,
                "channel": "access_control",
                "zone": zone,
                "command": command,
                "reason": reason,
                "alarm_id": alarm_id,
                "dispatched_at": self._ctx.clock.timestamp_iso(),
            },
        )


__all__ = [
    "BroadcastPort",
    "AccessControlPort",
    "LocalBroadcast",
    "LocalAccessControl",
    "ACCESS_COMMANDS",
    "LINKAGE_STREAM",
]
