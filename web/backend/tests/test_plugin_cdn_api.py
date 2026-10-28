from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from web.backend.core import plugin_api


@pytest.mark.asyncio
async def test_classify_mobile_ips_uses_current_classifier_and_unknown_fails_open():
    service = MagicMock()
    service.lookup_batch = AsyncMock(return_value={
        "1.1.1.1": SimpleNamespace(asn_org="PJSC MegaFon", connection_type="residential"),
        "2.2.2.2": SimpleNamespace(asn_org="Example ISP", connection_type="residential"),
        "3.3.3.3": SimpleNamespace(asn_org=None, connection_type="unknown"),
    })
    with patch.object(plugin_api, "geoip_service", return_value=service):
        result = await plugin_api.classify_mobile_ips(["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"])

    assert result == {
        "1.1.1.1": True,
        "2.2.2.2": False,
        "3.3.3.3": None,
        "4.4.4.4": None,
    }


@pytest.mark.asyncio
async def test_classify_mobile_ips_geoip_error_returns_unknown():
    service = MagicMock()
    service.lookup_batch = AsyncMock(side_effect=RuntimeError("geoip down"))
    with patch.object(plugin_api, "geoip_service", return_value=service):
        result = await plugin_api.classify_mobile_ips(["1.1.1.1"])
    assert result == {"1.1.1.1": None}


@pytest.mark.asyncio
async def test_live_cdn_ips_facade_delegates_by_node_and_tag():
    with patch("web.backend.api.v2.collector.live_cdn_ips_by_node", return_value={"n1": {"vk": ["1.2.3.4"]}}):
        result = await plugin_api.live_cdn_ips_by_node({"n1": ["vk"]})
    assert result == {"n1": {"vk": ["1.2.3.4"]}}


@pytest.mark.asyncio
async def test_push_cdn_policy_sends_signed_replace_command():
    conn = AsyncMock()
    conn.fetchrow = AsyncMock(return_value={"agent_token": "node-token", "agent_version": "1.10.0"})
    db = MagicMock(is_connected=True)
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=conn)
    context.__aexit__ = AsyncMock(return_value=False)
    db.acquire = MagicMock(return_value=context)
    manager = MagicMock()
    manager.is_connected.return_value = True
    manager.send_command = AsyncMock(return_value=True)

    with patch("shared.database.db_service", db), \
         patch("web.backend.core.agent_manager.agent_manager", manager):
        result = await plugin_api.push_cdn_policy(
            "node-1", [{"port": 4446, "action": "drop"}], ["1.2.3.4"],
        )

    assert result is True
    command = manager.send_command.await_args.args[1]
    assert command["type"] == "set_cdn_policy"
    assert command["command_id"] == "plugin:cdn_policy:policy"
    assert command["non_mobile_ips"] == ["1.2.3.4"]
    assert command["_sig"]


@pytest.mark.asyncio
async def test_push_cdn_policy_rejects_agent_before_1_10():
    conn = AsyncMock()
    conn.fetchrow = AsyncMock(return_value={"agent_token": "node-token", "agent_version": "1.9.0"})
    db = MagicMock(is_connected=True)
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=conn)
    context.__aexit__ = AsyncMock(return_value=False)
    db.acquire = MagicMock(return_value=context)
    manager = MagicMock()
    manager.is_connected.return_value = True
    manager.send_command = AsyncMock(return_value=True)

    with patch("shared.database.db_service", db), \
         patch("web.backend.core.agent_manager.agent_manager", manager):
        result = await plugin_api.push_cdn_policy("node-1", [], [])

    assert result is False
    manager.send_command.assert_not_awaited()


@pytest.mark.asyncio
async def test_panel_nodes_exposes_only_loopback_cdn_inbounds(monkeypatch):
    api = MagicMock()
    api.get_nodes = AsyncMock(return_value={"response": [{"uuid": "n1", "name": "Node 1"}]})
    api.get_node = AsyncMock(return_value={"response": {"uuid": "n1", "name": "Node 1", "configProfile": {
        "activeInbounds": [
            {"uuid": "cdn", "tag": "vk-cdn", "rawInbound": {"listen": "::1", "port": 4446}},
            {"uuid": "direct", "tag": "reality", "rawInbound": {"listen": "127.0.0.1", "port": 10443}},
        ],
    }}})
    monkeypatch.setattr(plugin_api, "panel_api", lambda: api)
    with patch("shared.api_client.api_client", api):
        result = await plugin_api.panel_nodes_with_inbounds()
    assert result == [{"uuid": "n1", "name": "Node 1", "inbounds": [
        {"uuid": "cdn", "tag": "vk-cdn", "port": 4446},
    ]}]