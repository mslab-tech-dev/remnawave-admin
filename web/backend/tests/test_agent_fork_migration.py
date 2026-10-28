from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path


def _migration(path: str, name: str):
    file = Path(__file__).resolve().parents[3] / "alembic" / "versions" / path
    spec = spec_from_file_location(name, file)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fleet_agent_update_script_is_repointed_to_fork():
    previous = _migration(
        "20260721_0090_update_agent_script_detached_restart.py", "old_agent_update",
    )
    current = _migration(
        "20261027_0128_switch_agent_updates_to_fork.py", "fork_agent_update",
    )
    script = current._migrate_update_script(previous.NEW_SCRIPT_CONTENT)

    assert current.FORK_TARBALL in script
    assert "git remote set-url origin https://github.com/mslab-tech-dev/remnawave-admin.git" in script
    assert "git fetch origin main --quiet" in script
    assert "git reset --hard FETCH_HEAD" in script
    assert "COMPOSE_FILE=" in script
    assert "ghcr.io/mslab-tech-dev/remnawave-admin-node-agent" in script
    assert "Cannot safely change a standalone container's image reference" in script
    assert "https://github.com/Case211/remnawave-admin/archive" not in script