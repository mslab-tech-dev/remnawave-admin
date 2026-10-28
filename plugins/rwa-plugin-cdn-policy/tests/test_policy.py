from unittest.mock import AsyncMock
from types import SimpleNamespace

import pytest

from rwa_plugin_cdn_policy import _confirmed_non_mobile


@pytest.mark.asyncio
async def test_only_confirmed_non_mobile_ipv4_is_returned(monkeypatch):
    from web.backend.core import plugin_api

    _confirmed_non_mobile.__globals__["_MOBILE_CACHE"].clear()
    lookup = AsyncMock(return_value={
        "1.2.3.4": False,
        "5.6.7.8": True,
        "9.10.11.12": None,
    })
    monkeypatch.setattr(plugin_api, "classify_mobile_ips", lookup)

    result = await _confirmed_non_mobile(None, [
        "1.2.3.4", "5.6.7.8", "9.10.11.12", "2001:db8::1",
    ])

    assert result == ["1.2.3.4"]
    lookup.assert_awaited_once_with(["1.2.3.4", "5.6.7.8", "9.10.11.12"])


@pytest.mark.asyncio
async def test_geoip_unknown_is_retried_but_never_shaped(monkeypatch):
    from web.backend.core import plugin_api

    cache = _confirmed_non_mobile.__globals__["_MOBILE_CACHE"]
    cache.clear()
    monkeypatch.setattr(_confirmed_non_mobile.__globals__["time"], "monotonic", lambda: 100.0)
    lookup = AsyncMock(return_value={"1.2.3.4": None})
    monkeypatch.setattr(plugin_api, "classify_mobile_ips", lookup)

    assert await _confirmed_non_mobile(None, ["1.2.3.4"]) == []
    assert cache["1.2.3.4"] == (None, 400.0)
    lookup.assert_awaited_once()


def test_plugin_build_registers_page_routes():
    from rwa_plugin_cdn_policy import _build

    parts = _build(SimpleNamespace(plugin_id="cdn_policy", settings=object()))
    paths = {route.path for route in parts.router.routes}
    assert {"/nodes", "/settings", "/status", "/sync", "/app"} <= paths
    assert parts.on_agent_connect is not None
    assert parts.on_agent_result is not None


def test_mobile_classifier_cache_is_bounded(monkeypatch):
    from rwa_plugin_cdn_policy import _cache_mobile

    cache = _confirmed_non_mobile.__globals__["_MOBILE_CACHE"]
    cache.clear()
    monkeypatch.setitem(_confirmed_non_mobile.__globals__, "_MOBILE_CACHE_MAX", 2)
    _cache_mobile("1.1.1.1", False, 10.0)
    _cache_mobile("2.2.2.2", True, 10.0)
    _cache_mobile("3.3.3.3", None, 10.0)
    assert list(cache) == ["2.2.2.2", "3.3.3.3"]