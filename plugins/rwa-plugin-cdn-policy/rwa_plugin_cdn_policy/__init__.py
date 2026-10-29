"""CDN per-inbound policy plugin (Plugin API v1)."""

import asyncio
import json
import ipaddress
from collections import OrderedDict
from pathlib import Path
import time
from typing import Literal, Optional

_MOBILE_CACHE: OrderedDict[str, tuple[Optional[bool], float]] = OrderedDict()
_MOBILE_CACHE_MAX = 65536
_GEOIP_LOOKUPS_PER_TICK = 20
_KNOWN_CACHE_SECONDS = 86400
_UNKNOWN_RETRY_SECONDS = 300
_LAST_SENT: dict[str, tuple[str, float]] = {}
_SYNC_LOCK = asyncio.Lock()


def _cache_mobile(ip: str, mobile: Optional[bool], expires_at: float) -> None:
    _MOBILE_CACHE[ip] = (mobile, expires_at)
    _MOBILE_CACHE.move_to_end(ip)
    while len(_MOBILE_CACHE) > _MOBILE_CACHE_MAX:
        _MOBILE_CACHE.popitem(last=False)


async def _push_node(node_uuid: str, rules: list[dict], non_mobile_ips: list[str]) -> bool:
    from web.backend.core.plugin_api import push_cdn_policy

    fingerprint = json.dumps([rules, non_mobile_ips], sort_keys=True, separators=(",", ":"))
    previous = _LAST_SENT.get(node_uuid)
    now = time.monotonic()
    if previous and previous[0] == fingerprint and now - previous[1] < 120:
        return True
    sent = await push_cdn_policy(node_uuid, rules, non_mobile_ips)
    if sent:
        _LAST_SENT[node_uuid] = (fingerprint, now)
    else:
        _LAST_SENT.pop(node_uuid, None)
    return sent


async def _confirmed_non_mobile(ctx, candidates: list[str]) -> list[str]:
    from web.backend.core.plugin_api import classify_mobile_ips

    now = time.monotonic()
    ipv4 = []
    for candidate in candidates:
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if address.version == 4:
            ipv4.append(str(address))
    ipv4 = sorted(set(ipv4))

    due = []
    for ip in ipv4:
        entry = _MOBILE_CACHE.get(ip)
        if entry is None or entry[1] <= now:
            due.append(ip)
        else:
            _MOBILE_CACHE.move_to_end(ip)
    for ip in due[:_GEOIP_LOOKUPS_PER_TICK]:
        _cache_mobile(ip, None, now + _UNKNOWN_RETRY_SECONDS)
    if due:
        looked_up = await classify_mobile_ips(due[:_GEOIP_LOOKUPS_PER_TICK])
        refreshed_at = time.monotonic()
        for ip, mobile in looked_up.items():
            ttl = _KNOWN_CACHE_SECONDS if mobile is not None else _UNKNOWN_RETRY_SECONDS
            _cache_mobile(ip, mobile, refreshed_at + ttl)

    return [ip for ip in ipv4 if _MOBILE_CACHE.get(ip, (None, 0))[0] is False]


def _own_version() -> str:
    from importlib.metadata import PackageNotFoundError, version

    try:
        return version("rwa-plugin-cdn-policy")
    except PackageNotFoundError:
        return "0.1.0"


async def _sync(ctx, only_node: Optional[str] = None) -> dict:
    async with _SYNC_LOCK:
        return await _sync_locked(ctx, only_node)


async def _sync_locked(ctx, only_node: Optional[str] = None) -> dict:
    from web.backend.core.plugin_api import live_cdn_ips_by_node

    config = await ctx.settings.get("policy", default=[])
    selected = [item for item in config if only_node is None or item["node_uuid"] == only_node]
    pushed = 0
    skipped = 0
    prepared = []

    for node in selected:
        inbound_policies = node.get("inbounds") or []
        tags = [item["tag"] for item in inbound_policies]
        live = await live_cdn_ips_by_node({node["node_uuid"]: tags})
        by_tag = live.get(node["node_uuid"].lower(), {})
        candidates = sorted({ip for addresses in by_tag.values() for ip in addresses})
        prepared.append((node, inbound_policies, candidates))

    all_candidates = sorted({ip for _, _, candidates in prepared for ip in candidates})
    confirmed_non_mobile = set(await _confirmed_non_mobile(ctx, all_candidates))
    for node, inbound_policies, candidates in prepared:
        non_mobile = sorted(confirmed_non_mobile.intersection(candidates))
        rules = []
        for item in inbound_policies:
            rule = {"port": item["port"], "action": item["action"]}
            if item["action"] == "shape":
                rule["rate_kbit"] = item["rate_kbit"]
            rules.append(rule)
        if await _push_node(node["node_uuid"], rules, non_mobile):
            pushed += 1
        else:
            skipped += 1

    retired = set(await ctx.settings.get("retired_nodes", default=[]))
    retired_targets = retired if only_node is None else retired.intersection({only_node})
    for node_uuid in retired_targets:
        if await _push_node(node_uuid, [], []):
            pushed += 1
        else:
            skipped += 1

    return {"pushed": pushed, "offline": skipped}


def _build(ctx):
    from fastapi import APIRouter, Depends, HTTPException, Response
    from pydantic import BaseModel, ConfigDict, Field, model_validator

    from web.backend.core.plugin_api import auth_deps
    from web.backend.core.plugins import PluginParts, ScheduledTask

    AdminUser, require_permission = auth_deps()
    router = APIRouter()

    class InboundPolicy(BaseModel):
        model_config = ConfigDict(extra="forbid")
        tag: str = Field(min_length=1, max_length=128)
        port: int = Field(ge=1, le=65535)
        action: Literal["shape", "drop"]
        rate_kbit: Optional[int] = Field(default=None, ge=1, le=100_000_000)

        @model_validator(mode="after")
        def validate_rate(self):
            if self.action == "shape" and self.rate_kbit is None:
                raise ValueError("rate_kbit is required for shape")
            if self.action == "drop" and self.rate_kbit is not None:
                raise ValueError("rate_kbit is not used for drop")
            return self

    class NodePolicy(BaseModel):
        model_config = ConfigDict(extra="forbid")
        node_uuid: str = Field(min_length=1, max_length=64)
        inbounds: list[InboundPolicy] = Field(min_length=1, max_length=64)

        @model_validator(mode="after")
        def unique_ports(self):
            ports = [item.port for item in self.inbounds]
            if len(ports) != len(set(ports)):
                raise ValueError("inbound ports must be unique on a node")
            return self

    class SettingsIn(BaseModel):
        model_config = ConfigDict(extra="forbid")
        nodes: list[NodePolicy] = Field(default_factory=list, max_length=256)

        @model_validator(mode="after")
        def unique_nodes(self):
            uuids = [item.node_uuid for item in self.nodes]
            if len(uuids) != len(set(uuids)):
                raise ValueError("node UUIDs must be unique")
            return self

    @router.get("/nodes")
    async def get_nodes(
        admin: AdminUser = Depends(require_permission("cdn_policy", "view")),
    ):
        from web.backend.core.plugin_api import check_node_access, panel_nodes_with_inbounds
        nodes = await panel_nodes_with_inbounds()
        visible = []
        for node in nodes:
            if node["inbounds"] and await check_node_access(admin, node["uuid"], "edit"):
                visible.append(node)
        return visible

    @router.get("/settings")
    async def get_settings(
        admin: AdminUser = Depends(require_permission("cdn_policy", "view")),
    ):
        from web.backend.core.plugin_api import check_node_access
        policies = await ctx.settings.get("policy", default=[])
        visible = [
            item for item in policies
            if await check_node_access(admin, item["node_uuid"], "view")
        ]
        return {"nodes": visible}

    @router.get("/status")
    async def get_status(
        admin: AdminUser = Depends(require_permission("cdn_policy", "view")),
    ):
        from web.backend.core.plugin_api import check_node_access
        status = await ctx.settings.get("status", default={})
        visible = {}
        for node_uuid, value in status.items():
            if await check_node_access(admin, node_uuid, "view"):
                visible[node_uuid] = value
        return visible

    @router.put("/settings")
    async def put_settings(
        data: SettingsIn,
        admin: AdminUser = Depends(require_permission("cdn_policy", "edit")),
    ):
        from web.backend.core.plugin_api import check_node_access, panel_nodes_with_inbounds

        current = await ctx.settings.get("policy", default=[])
        nodes = [item.model_dump(exclude_none=True) for item in data.nodes]
        node_index = {node["uuid"]: node for node in await panel_nodes_with_inbounds()}
        target_ids = {item["node_uuid"] for item in nodes}
        preserved = []
        editable_current = []
        for item in current:
            if await check_node_access(admin, item["node_uuid"], "edit"):
                editable_current.append(item)
            else:
                preserved.append(item)
        for node_uuid in target_ids:
            if not await check_node_access(admin, node_uuid, "edit"):
                raise HTTPException(status_code=403, detail="node access denied")
        for item in nodes:
            available = {
                (inbound["tag"], inbound["port"])
                for inbound in node_index.get(item["node_uuid"], {}).get("inbounds", [])
            }
            # nodes уже прошли model_dump(), поэтому правила здесь — словари,
            # а не объекты InboundPolicy: обращение к .tag падало в 500.
            if any((rule["tag"], rule["port"]) not in available for rule in item["inbounds"]):
                raise HTTPException(status_code=422, detail="inbound is not a loopback CDN inbound")
        merged = preserved + nodes
        await ctx.settings.set("policy", merged)
        new_ids = {item["node_uuid"] for item in merged}
        retired = set(await ctx.settings.get("retired_nodes", default=[]))
        for old in editable_current:
            if old["node_uuid"] not in new_ids:
                retired.add(old["node_uuid"])
        retired.difference_update(new_ids)
        await ctx.settings.set("retired_nodes", sorted(retired))
        return {"success": True, "sync": await _sync(ctx)}

    @router.post("/sync")
    async def sync_now(
        admin: AdminUser = Depends(require_permission("cdn_policy", "edit")),
    ):
        from web.backend.core.plugin_api import check_node_access
        policy = await ctx.settings.get("policy", default=[])
        node_ids = {item["node_uuid"] for item in policy}
        node_ids.update(await ctx.settings.get("retired_nodes", default=[]))
        for node_uuid in node_ids:
            if not await check_node_access(admin, node_uuid, "edit"):
                raise HTTPException(status_code=403, detail="node access denied")
        return await _sync(ctx)

    bundle = (Path(__file__).parent / "static" / "app.js").read_text(encoding="utf-8")

    @router.get("/app")
    async def app_bundle(
        _admin: AdminUser = Depends(require_permission("cdn_policy", "view")),
    ) -> Response:
        return Response(bundle, media_type="application/javascript")

    async def tick() -> None:
        await _sync(ctx)

    async def on_agent_connect(node_uuid: str, _token: str) -> None:
        _LAST_SENT.pop(node_uuid, None)
        await _sync(ctx, only_node=node_uuid)

    async def on_agent_result(node_uuid: str, msg: dict) -> None:
        from datetime import datetime, timezone

        status = await ctx.settings.get("status", default={})
        status[node_uuid] = {
            "state": msg.get("status", "unknown"),
            "output": str(msg.get("output") or "")[-2000:],
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        await ctx.settings.set("status", status)
        if msg.get("status") == "completed":
            retired = set(await ctx.settings.get("retired_nodes", default=[]))
            if node_uuid in retired:
                retired.remove(node_uuid)
                await ctx.settings.set("retired_nodes", sorted(retired))
        else:
            _LAST_SENT.pop(node_uuid, None)

    return PluginParts(
        router=router,
        scheduled_tasks=[ScheduledTask(name="cdn-policy-sync", interval_seconds=30, coro=tick)],
        on_agent_connect=on_agent_connect,
        on_agent_result=on_agent_result,
    )


def manifest():
    from web.backend.core.plugins import NavEntry, PluginManifest, PluginUI

    return PluginManifest(
        id="cdn_policy",
        name="CDN Policy",
        version=_own_version(),
        api_version=1,
        billing="free",
        build=_build,
        rbac_resources={"cdn_policy": ["view", "edit"]},
        navigation=[
            NavEntry(
                path="/plugins/cdn-policy",
                label_i18n="CDN policy",
                icon="Activity",
                permission=("cdn_policy", "view"),
            ),
        ],
        ui=PluginUI(kind="module", path="/app"),
    )