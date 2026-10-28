"""Switch the persisted node-agent updater from upstream to this fork.

Revision ID: 0128
Revises: 0127

Installed panels keep the built-in Fleet script in node_scripts, so editing
older migration files would not update them. Rewrite the stored script once:
- source checkouts follow the fork's origin/main;
- bare installs download the fork tarball;
- compose deployments switch their agent image before pulling it.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0128"
down_revision: Union[str, None] = "0127"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

FORK_REPO = "https://github.com/mslab-tech-dev/remnawave-admin"
FORK_TARBALL = f"{FORK_REPO}/archive/refs/heads/main.tar.gz"
FORK_AGENT_IMAGE = "ghcr.io/mslab-tech-dev/remnawave-admin-node-agent"


def _migrate_update_script(script: str) -> str:
    script = script.replace(
        "https://github.com/Case211/remnawave-admin/archive/refs/heads/main.tar.gz",
        FORK_TARBALL,
    )
    script = script.replace(
        "git fetch --all --quiet\n    git reset --hard origin/main",
        f"git remote set-url origin {FORK_REPO}.git\n    git fetch origin main --quiet\n    git reset --hard FETCH_HEAD",
    )

    old_compose = '''        echo "Pulling latest image..."
        cd "$COMPOSE_DIR"
        docker compose pull "$COMPOSE_SERVICE" 2>&1 | tail -5'''
    new_compose = f'''        echo "Switching compose agent image to {FORK_AGENT_IMAGE}:latest"
        cd "$COMPOSE_DIR"
        COMPOSE_FILE=""
        for candidate in compose.yaml compose.yml docker-compose.yaml docker-compose.yml; do
            if [ -f "$candidate" ]; then COMPOSE_FILE="$candidate"; break; fi
        done
        if [ -z "$COMPOSE_FILE" ]; then
            echo "ERROR: compose file not found; refusing to pull an unknown agent image"
            exit 1
        fi
        if grep -Fq 'ghcr.io/case211/remnawave-admin-node-agent' "$COMPOSE_FILE"; then
            sed -i 's#ghcr.io/case211/remnawave-admin-node-agent#{FORK_AGENT_IMAGE}#g' "$COMPOSE_FILE"
        elif ! grep -Fq '{FORK_AGENT_IMAGE}' "$COMPOSE_FILE"; then
            echo "ERROR: agent image is not the expected upstream or fork image"
            exit 1
        fi
        docker compose pull "$COMPOSE_SERVICE" 2>&1 | tail -5'''
    script = script.replace(old_compose, new_compose)

    old_bare_docker = '''    else
        echo "Pulling latest image..."
        docker pull "$OLD_IMAGE" 2>&1 | tail -5'''
    new_bare_docker = '''    else
        case "$OLD_IMAGE" in
            ghcr.io/*/remnawave-admin-node-agent:*)
                echo "Cannot safely change a standalone container's image reference."
                echo "Use the fork installer to recreate it from its compose file."
                exit 1
                ;;
        esac
        echo "Pulling latest image..."
        docker pull "$OLD_IMAGE" 2>&1 | tail -5'''
    script = script.replace(old_bare_docker, new_bare_docker)
    return script


def upgrade() -> None:
    conn = op.get_bind()
    row = conn.execute(
        sa.text("SELECT script_content FROM node_scripts WHERE name = 'update_agent'")
    ).scalar_one_or_none()
    if row is None:
        return
    conn.execute(
        sa.text(
            "UPDATE node_scripts SET script_content = :content, updated_at = NOW() "
            "WHERE name = 'update_agent'"
        ),
        {"content": _migrate_update_script(str(row))},
    )


def downgrade() -> None:
    # Keep the fork-aware updater in place; reverting would repoint nodes to upstream.
    pass
