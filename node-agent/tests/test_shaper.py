"""Шейпер клиентов: разбор команды, раскладка карты и скрипты tc/bpftool.

Живая проверка программы eBPF идёт стендом на ядре; здесь — то, что
агент собирает из команды панели, и правила «снимаем только своё».

    cd node-agent && python -m pytest
"""
import json
import os
import shutil
import struct
import subprocess

os.environ.setdefault("AGENT_NODE_UUID", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
os.environ.setdefault("AGENT_COLLECTOR_URL", "http://collector.test")
os.environ.setdefault("AGENT_AUTH_TOKEN", "token")

from unittest.mock import AsyncMock, MagicMock

import pytest

from src import shaper
from src.command_runner import ALLOWED_COMMAND_TYPES, CommandRunner

BASE = {"enabled": True, "ports": [443], "down_kbit": 10000, "up_kbit": 5000}


def cfg(**overrides):
    return shaper.parse_config({**BASE, **overrides})


class TestParseConfig:
    def test_disabled_needs_nothing_else(self):
        assert shaper.parse_config({"enabled": False, "ports": "garbage"}).enabled is False

    def test_ports_are_deduplicated_and_sorted(self):
        assert cfg(ports=[8443, 443, 443]).ports == (443, 8443)

    @pytest.mark.parametrize("ports", [[], [0], [70000], ["443; rm -rf /"], [True], "443"])
    def test_bad_ports_are_rejected(self, ports):
        with pytest.raises(ValueError):
            cfg(ports=ports)

    def test_empty_ports_would_shape_the_node_itself(self):
        """Без портов под потолок попали бы соединения ноды в интернет."""
        with pytest.raises(ValueError, match="inbound port"):
            cfg(ports=[])

    def test_too_many_ports_do_not_fit_the_map(self):
        with pytest.raises(ValueError):
            cfg(ports=list(range(1000, 1000 + shaper.MAX_PORTS + 1)))

    def test_something_must_be_limited(self):
        with pytest.raises(ValueError, match="nothing to shape"):
            cfg(down_kbit=0, up_kbit=0)

    def test_penalty_alone_is_enough(self):
        c = cfg(down_kbit=0, up_kbit=0,
                penalty={"enabled": True, "mb": 500, "window_sec": 60, "kbit": 5000, "minutes": 10})
        assert (c.penalty_mb, c.penalty_window_sec, c.penalty_kbit, c.penalty_minutes) == (500, 60, 5000, 10)

    def test_disabled_penalty_ignores_its_fields(self):
        c = cfg(penalty={"enabled": False, "mb": "junk"})
        assert c.penalty_mb == 0

    @pytest.mark.parametrize("penalty", [
        {"enabled": True, "mb": 0, "window_sec": 60, "kbit": 5000, "minutes": 10},
        {"enabled": True, "mb": 100, "window_sec": 1, "kbit": 5000, "minutes": 10},
        {"enabled": True, "mb": 100, "window_sec": 60, "kbit": 1, "minutes": 10},
        {"enabled": True, "mb": 100, "window_sec": 60, "kbit": 5000},
    ])
    def test_bad_penalty_is_rejected(self, penalty):
        with pytest.raises(ValueError):
            cfg(penalty=penalty)

    def test_rates_are_bounded(self):
        with pytest.raises(ValueError):
            cfg(down_kbit=-1)
        with pytest.raises(ValueError):
            cfg(up_kbit=shaper.MAX_KBIT + 1)


class TestEncoding:
    def test_cfg_layout_matches_the_bpf_struct(self):
        """struct shaper_cfg — девять __u64 в этом порядке."""
        c = cfg(penalty={"enabled": True, "mb": 100, "window_sec": 60, "kbit": 2000, "minutes": 5})
        fields = struct.unpack("<9Q", shaper.encode_cfg(c, 14))
        assert fields == (
            14,
            10000 * 125,              # кбит/с → байт/с
            5000 * 125,
            shaper.HORIZON_NS,
            shaper.BURST_NS,
            100 * 1024 * 1024,
            60 * 10**9,
            2000 * 125,
            5 * 60 * 10**9,
        )

    def test_port_key_is_little_endian_u16(self):
        script = shaper.build_apply_script(cfg(ports=[443]))
        assert "rws_ports key hex bb 01 value hex 01" in script


class TestCdnLabels:
    @pytest.mark.parametrize("ip,expected", [
        ("5.165.208.52", "fd 00 00 01 00 00 00 00 00 05 01 65 02 08 00 52"),
        ("82.200.17.67", "fd 00 00 01 00 00 00 00 00 82 02 00 00 17 00 67"),
        ("178.177.222.58", "fd 00 00 01 00 00 00 00 01 78 01 77 02 22 00 58"),
        ("1.2.3.4", "fd 00 00 01 00 00 00 00 00 01 00 02 00 03 00 04"),
        ("10.0.0.1", "fd 00 00 01 00 00 00 00 00 10 00 00 00 00 00 01"),
        ("255.255.255.255", "fd 00 00 01 00 00 00 00 02 55 02 55 02 55 02 55"),
    ])
    def test_cdn_label_key_vectors(self, ip, expected):
        assert shaper._hex(shaper.cdn_label_key(ip)) == expected

    def test_cdn_label_key_is_injective_for_each_octet(self):
        keys = {shaper.cdn_label_key(f"{octet}.{octet}.{octet}.{octet}")
                for octet in range(256)}
        assert len(keys) == 256

    def test_cdn_label_key_matches_nginx_text_form(self):
        ip = "5.165.208.52"
        label = "fd00:1::5:165:208:52"
        assert shaper.cdn_label_key(ip) == __import__("ipaddress").IPv6Address(label).packed

    def test_ipv6_clients_have_no_label(self):
        assert shaper.cdn_label_key("2001:db8::1") is None
        rules, skipped = shaper.cdn_personal({"2001:db8::1": 1024})
        assert rules == {}
        assert skipped == 1

    def test_cdn_personal_translates_ipv4_and_counts_ipv6(self):
        rules, skipped = shaper.cdn_personal({
            "5.165.208.52": 512,
            "2001:db8::1": 1024,
        })
        assert rules == {"fd00:1::5:165:208:52": 512}
        assert skipped == 1

    def test_cdn_policy_parses_shape_and_drop(self):
        rules, skipped = shaper.parse_cdn_policy([
            {"port": 4446, "action": "shape", "rate_kbit": 1024},
            {"port": 4445, "action": "drop"},
            {"port": 4444, "action": "other"},
        ])
        assert rules == {
            4446: (shaper.CDN_SHAPE, 1024),
            4445: (shaper.CDN_DROP, 0),
        }
        assert skipped == 1

    def test_policy_clients_accept_only_ipv4(self):
        ips, skipped = shaper.parse_cdn_clients(["1.2.3.4", "2001:db8::1", "bad"])
        assert ips == {"1.2.3.4"}
        assert skipped == 2

    def test_cdn_policy_encoding_uses_one_rate_in_both_directions(self):
        assert struct.unpack("<3Q", shaper.encode_cdn_policy(shaper.CDN_SHAPE, 1024)) == (
            1024 * 125, 1024 * 125, shaper.CDN_SHAPE,
        )
        assert struct.unpack("<3Q", shaper.encode_cdn_policy(shaper.CDN_DROP)) == (
            0, 0, shaper.CDN_DROP,
        )

    def test_apply_and_update_use_isolated_pins_and_lo_keys(self):
        apply = shaper.build_cdn_apply_script(
            {"1.2.3.4": 512}, {4446: (shaper.CDN_SHAPE, 1024)}, {"5.6.7.8"},
        )
        assert shaper.CDN_PIN_DIR in apply
        assert "IFACE=\"lo\"" in apply
        assert 'CFG="0e 00 00 00 00 00 00 00' in apply
        assert "rws_cdn_rules key hex 5e 11" in apply
        assert "rws_cdn_clients key hex" in apply
        assert apply.index("rws_cdn_rules key") < apply.index("bpf da pinned")

        update = shaper.build_cdn_update_script(rules_set={4446: (shaper.CDN_DROP, 0)})
        assert f"exit {shaper.RELOAD_EXIT}" in update
        assert "map update pinned" in update

    def test_cdn_disable_only_removes_owned_filters_and_root(self):
        script = shaper.build_cdn_disable_script()
        assert f"pref {shaper.SHAPER_PREF}" in script
        assert f'"{shaper.CDN_ROOT_HANDLE}"' in script
        assert f"umount {shaper.CDN_PIN_DIR}" in script


class TestApplyScript:
    def test_previous_install_is_removed_only_if_it_is_ours(self):
        script = shaper.build_apply_script(cfg())
        assert f"*rws_*) tc filter del dev \"$IFACE\" $HOOK pref {shaper.SHAPER_PREF}" in script
        assert "is taken by another tool\"; exit 1" in script
        # Удаление без номера приоритета снесло бы все фильтры интерфейса
        deletions = [line for line in script.splitlines() if "tc filter del" in line]
        assert all(f"pref {shaper.SHAPER_PREF}" in line or f"pref {shaper.LEGACY_IFB_PREF}" in line
                   for line in deletions)

    def test_fq_is_installed_only_over_the_kernel_default(self):
        script = shaper.build_apply_script(cfg())
        lines = script.splitlines()
        installs = [i for i, line in enumerate(lines) if "tc qdisc replace" in line and "root" in line]
        assert installs
        guard = next(i for i, line in enumerate(lines) if 'elif [ "$HANDLE" = "0:" ]' in line)
        foreign = next(i for i, line in enumerate(lines) if "ROOT=foreign" in line)
        assert all(guard < i < foreign for i in installs)
        assert all(f"handle {shaper.ROOT_HANDLE}" in lines[i] for i in installs)

    def test_failed_install_gives_the_root_back(self):
        """Упали после того, как поставили свой fq, — корень возвращается ядру.
        Чужой или уже стоявший корень откат не трогает: NEWROOT ставится только
        в ветке, где fq поставили мы."""
        lines = shaper.build_apply_script(cfg()).splitlines()
        trap = next(i for i, line in enumerate(lines) if line.startswith("trap "))
        assert 'tc qdisc del dev "$IFACE" root' in lines[trap]
        assert '[ -n "$NEWROOT" ]' in lines[trap] and '[ "$RC" -ne 0 ]' in lines[trap]
        guard = next(i for i, line in enumerate(lines) if 'elif [ "$HANDLE" = "0:" ]' in line)
        foreign = next(i for i, line in enumerate(lines) if "ROOT=foreign" in line)
        marks = [i for i, line in enumerate(lines) if line.strip() == "NEWROOT=1"]
        assert marks and all(guard < i < foreign for i in marks)
        # Ловушка ставится раньше, чем что-либо меняется на интерфейсе
        first_change = next(i for i, line in enumerate(lines)
                            if i != trap and ("tc qdisc del" in line or "tc filter del" in line))
        assert trap < first_change

    def test_both_hooks_get_the_program(self):
        script = shaper.build_apply_script(cfg())
        assert f"egress pref {shaper.SHAPER_PREF} bpf da pinned {shaper.PIN_DIR}/progs/rws_egress" in script
        assert f"ingress pref {shaper.SHAPER_PREF} bpf da pinned {shaper.PIN_DIR}/progs/rws_ingress" in script

    def test_maps_are_configured_before_the_program_is_attached(self):
        script = shaper.build_apply_script(cfg())
        assert script.index("rws_cfg key") < script.index("bpf da pinned")
        assert script.index("rws_ports key") < script.index("bpf da pinned")

    def test_existing_clsact_is_reused(self):
        lines = shaper.build_apply_script(cfg()).splitlines()
        add = next(i for i, line in enumerate(lines) if 'tc qdisc add dev "$IFACE" clsact' in line)
        assert any("^qdisc clsact " in line and line.startswith("if !") for line in lines[:add])

    def test_l2_header_follows_the_link_type(self):
        script = shaper.build_apply_script(cfg())
        eth = " ".join(f"{b:02x}" for b in shaper.encode_cfg(cfg(), 14))
        l3 = " ".join(f"{b:02x}" for b in shaper.encode_cfg(cfg(), 0))
        assert f'CFG="{eth}"' in script and f'CFG="{l3}"' in script
        assert "link/ether" in script


class TestDisableScript:
    def test_foreign_filters_do_not_fail_the_removal(self):
        script = shaper.build_disable_script()
        assert 'echo "FOREIGN=$HOOK"' in script
        assert "exit 1 ;;" not in script

    def test_root_is_removed_only_when_it_carries_our_mark(self):
        lines = shaper.build_disable_script().splitlines()
        removals = [i for i, line in enumerate(lines) if 'tc qdisc del dev "$IFACE" root' in line]
        # Каждое снятие корня — под своей меткой: наш fq или старая раскладка агента
        assert removals
        for i in removals:
            guard = lines[i - 1]
            assert f'= "{shaper.ROOT_HANDLE}" ]' in guard or "htb 40: parent 1:4" in guard

    def test_clsact_is_removed_only_when_nothing_else_is_on_it(self):
        lines = shaper.build_disable_script().splitlines()
        removal = next(i for i, line in enumerate(lines) if 'tc qdisc del dev "$IFACE" clsact' in line)
        guard = lines[removal - 1]
        assert '"$HAD"' in guard and "egress" in guard and "ingress" in guard


@pytest.mark.parametrize("script", [
    shaper.build_apply_script(cfg(ports=[443, 8443],
                                  penalty={"enabled": True, "mb": 1, "window_sec": 10, "kbit": 64, "minutes": 1})),
    shaper.build_disable_script(),
    shaper.build_cdn_apply_script(
        {"1.2.3.4": 512}, {4446: (shaper.CDN_SHAPE, 1024)}, {"5.6.7.8"},
    ),
    shaper.build_cdn_update_script(
        {"1.2.3.4": 512}, ["9.9.9.9"], {4446: (shaper.CDN_DROP, 0)}, [4445],
        ["5.6.7.8"], ["7.7.7.7"],
    ),
    shaper.build_cdn_disable_script(),
])
def test_scripts_are_valid_posix_shell(script):
    """В контейнере агента скрипт исполняет /bin/sh — у Debian это dash."""
    sh = shutil.which("dash") or shutil.which("sh")
    if not sh:
        pytest.skip("no POSIX shell to check the syntax with")
    # Байтами, а не текстом: на Windows текстовый режим дописал бы к строкам CR
    result = subprocess.run([sh, "-n"], input=script.encode(), capture_output=True)
    assert result.returncode == 0, result.stderr.decode(errors="replace")


class TestSummary:
    def test_installed_fq_means_exact_download_shaping(self):
        out = "IFACE=ens3\nROOT=installed:fq_codel\nsome tc noise\nACTIVE=1\n"
        state = shaper.summarize(cfg(), out, 0)
        assert state == {"enabled": True, "active": True, "loaded": True, "personal": 0,
                         "interface": "ens3", "root": "installed:fq_codel",
                         "download_exact": True, "error": None}

    def test_program_kept_for_personal_limits_is_not_an_active_general_shaper(self):
        """Общий шейпер выключен, программа стоит ради урезанных юзеров."""
        state = shaper.summarize(shaper.DISABLED, "ROOT=kept:fq\nACTIVE=1\n", 0, personal=3)
        assert state["active"] is False
        assert state["loaded"] is True and state["personal"] == 3

    def test_foreign_root_is_reported_as_rough_download(self):
        state = shaper.summarize(cfg(), "IFACE=ens3\nROOT=foreign:htb\nACTIVE=1\n", 0)
        assert state["active"] is True
        assert state["download_exact"] is False

    def test_failure_carries_the_reason(self):
        out = "IFACE=ens3\nERROR=egress pref 29304 on ens3 is taken by another tool\n"
        state = shaper.summarize(cfg(), out, 1)
        assert state["active"] is False
        assert "taken by another tool" in state["error"]

    def test_unexpected_failure_falls_back_to_the_last_line(self):
        state = shaper.summarize(cfg(), "IFACE=ens3\nlibbpf: prog 'rws_egress': failed to load\n", 255)
        assert state["error"] == "libbpf: prog 'rws_egress': failed to load"


def runner():
    r = CommandRunner.__new__(CommandRunner)
    r._settings = MagicMock(host_mode=False, cdn_shaping_enabled=False)
    r._shaper_general = shaper.DISABLED
    r._shaper_personal = {}
    r._shaper_loaded = False
    r._shaper_state = None
    r._cdn_personal = {}
    r._cdn_rules = {}
    r._cdn_clients = set()
    r._cdn_loaded = False
    r._run_hostnet = AsyncMock(return_value=("IFACE=ens3\nROOT=kept:fq\nACTIVE=1\n", 0))
    r._send = AsyncMock()
    return r


class TestCommand:
    def test_command_is_allowed(self):
        assert "set_shaper" in ALLOWED_COMMAND_TYPES

    @pytest.mark.asyncio
    async def test_apply_answers_with_state(self):
        r = runner()
        await r._set_shaper({**BASE, "type": "set_shaper", "command_id": "shaper"})

        script = r._run_hostnet.await_args.args[0]
        assert "bpftool prog loadall" in script
        reply = r._send.await_args.args[0]
        assert reply["command_id"] == "shaper"
        assert reply["status"] == "completed"
        assert json.loads(reply["output"])["active"] is True

    @pytest.mark.asyncio
    async def test_same_settings_on_reconnect_do_not_reinstall(self):
        """Панель шлёт настройки при каждом подключении агента; переустановка
        сбросила бы счётчики клиентов и снятые штрафы качальщиков."""
        r = runner()
        msg = {**BASE, "type": "set_shaper", "command_id": "shaper"}
        await r._set_shaper(msg)
        await r._set_shaper(msg)

        assert r._run_hostnet.await_count == 1
        reply = r._send.await_args.args[0]
        assert reply["status"] == "completed"
        assert json.loads(reply["output"])["active"] is True

    @pytest.mark.asyncio
    async def test_changed_settings_reinstall(self):
        r = runner()
        await r._set_shaper({**BASE, "type": "set_shaper", "command_id": "shaper"})
        await r._set_shaper({**BASE, "type": "set_shaper", "command_id": "shaper",
                             "down_kbit": BASE["down_kbit"] + 1000})
        assert r._run_hostnet.await_count == 2

    @pytest.mark.asyncio
    async def test_failed_install_is_retried(self):
        r = runner()
        r._run_hostnet = AsyncMock(return_value=("IFACE=ens3\nERROR=boom\n", 1))
        msg = {**BASE, "type": "set_shaper", "command_id": "shaper"}
        await r._set_shaper(msg)
        await r._set_shaper(msg)
        assert r._run_hostnet.await_count == 2

    @pytest.mark.asyncio
    async def test_personal_limits_survive_disabling_the_general_shaper(self):
        r = runner()
        r._shaper_personal = {"1.2.3.4": 1024}
        await r._set_shaper({"type": "set_shaper", "command_id": "shaper", "enabled": False})

        script = r._run_hostnet.await_args.args[0]
        assert "bpftool prog loadall" in script and "rws_personal key hex" in script
        assert "rws_ports key" not in script

    @pytest.mark.asyncio
    async def test_disable_runs_the_removal(self):
        r = runner()
        r._run_hostnet = AsyncMock(return_value=("IFACE=ens3\nROOT=restored\nACTIVE=0\n", 0))
        await r._set_shaper({"type": "set_shaper", "command_id": "shaper", "enabled": False})

        assert "bpftool prog loadall" not in r._run_hostnet.await_args.args[0]
        state = json.loads(r._send.await_args.args[0]["output"])
        assert state["enabled"] is False and state["root"] == "restored"

    @pytest.mark.asyncio
    async def test_invalid_command_never_reaches_the_shell(self):
        r = runner()
        await r._set_shaper({"type": "set_shaper", "command_id": "shaper", "enabled": True,
                             "ports": ["443; rm -rf /"], "down_kbit": 1000})

        r._run_hostnet.assert_not_awaited()
        reply = r._send.await_args.args[0]
        assert reply["status"] == "error"
        assert json.loads(reply["output"])["active"] is False


class TestCdnCommand:
    @pytest.mark.asyncio
    async def test_cdn_policy_is_rejected_when_opt_in_is_disabled(self):
        r = runner()
        await r._set_cdn_policy({"command_id": "cdn-policy", "rules": []})
        r._run_hostnet.assert_not_awaited()
        assert r._send.await_args.args[0]["status"] == "error"

    @pytest.mark.asyncio
    async def test_first_policy_installs_only_confirmed_non_mobile_clients(self):
        r = runner()
        r._settings.cdn_shaping_enabled = True
        await r._set_cdn_policy({
            "command_id": "cdn-policy",
            "rules": [{"port": 4446, "action": "shape", "rate_kbit": 1024}],
            "non_mobile_ips": ["5.165.208.52", "2001:db8::1"],
        })

        script = r._run_hostnet.await_args.args[0]
        assert "rws_cdn_rules key hex 5e 11" in script
        assert "rws_cdn_clients key hex fd 00 00 01" in script
        assert "2001:db8::1" not in script
        assert r._cdn_clients == {"5.165.208.52"}

    @pytest.mark.asyncio
    async def test_policy_update_changes_only_map_entries(self):
        r = runner()
        r._settings.cdn_shaping_enabled = True
        r._cdn_loaded = True
        r._cdn_rules = {4446: (shaper.CDN_SHAPE, 1024)}
        r._cdn_applied_rules = dict(r._cdn_rules)
        r._cdn_applied_personal = {}
        r._cdn_applied_clients = set()
        r._run_hostnet = AsyncMock(return_value=("UPDATED=1\n", 0))

        await r._set_cdn_policy({
            "command_id": "cdn-policy",
            "rules": [{"port": 4446, "action": "drop"}],
            "non_mobile_ips": ["1.2.3.4"],
        })

        script = r._run_hostnet.await_args.args[0]
        assert "prog loadall" not in script
        assert "rws_cdn_rules key" in script
        assert "rws_cdn_clients key" in script

    @pytest.mark.asyncio
    async def test_personal_throttle_sync_also_updates_cdn_map(self):
        r = runner()
        r._settings.cdn_shaping_enabled = True
        await r._sync_throttled_ips({"rules": [{"ip": "5.165.208.52", "rate_kbit": 512}]})

        assert r._run_hostnet.await_count == 2
        cdn_script = r._run_hostnet.await_args_list[1].args[0]
        assert "rws_personal key hex fd 00 00 01" in cdn_script

    @pytest.mark.asyncio
    async def test_cdn_failure_is_reported_without_hiding_eth0_success(self):
        r = runner()
        r._settings.cdn_shaping_enabled = True
        r._run_hostnet = AsyncMock(side_effect=[("ETH0=OK\n", 0), ("ERROR=lo failed\n", 1)])
        await r._sync_throttled_ips({"command_id": "throttle", "rules": [{"ip": "1.2.3.4", "rate_kbit": 512}]})

        result = r._send.await_args.args[0]
        assert result["status"] == "error"
        assert "ETH0=OK" in result["output"]
        assert "CDN:" in result["output"]
