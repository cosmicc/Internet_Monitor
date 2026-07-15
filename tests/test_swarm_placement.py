"""Tests for manager-side preferred-node placement reconciliation."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RECONCILER = (
    PROJECT_ROOT
    / "deploy"
    / "swarm-placement"
    / "internet-monitor-placement-reconciler"
)


FAKE_DOCKER = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import re
import sys

state_path = Path(os.environ["FAKE_DOCKER_STATE"])
log_path = Path(os.environ["FAKE_DOCKER_LOG"])
state = json.loads(state_path.read_text(encoding="utf-8"))
arguments = sys.argv[1:]

with log_path.open("a", encoding="utf-8") as log_file:
    log_file.write(json.dumps(arguments) + "\n")

if arguments[:2] == ["info", "--format"]:
    local_node_id = state.get("local_node_id", "manager")
    print(
        f"active|true|{local_node_id}"
        if state.get("manager", True)
        else f"inactive|false|{local_node_id}"
    )
elif arguments[:2] == ["service", "inspect"]:
    if not state.get("service_exists", True):
        raise SystemExit(1)
    if "--format" in arguments:
        print("\n".join(state.get("constraints", [])))
    else:
        print("[]")
elif arguments[:2] == ["service", "update"]:
    if "--constraint-add" in arguments:
        index = arguments.index("--constraint-add")
        state.setdefault("constraints", []).append(arguments[index + 1])
    elif "--constraint-rm" in arguments:
        index = arguments.index("--constraint-rm")
        removed = arguments[index + 1].replace(" ", "")
        state["constraints"] = [
            item for item in state.get("constraints", [])
            if item.replace(" ", "") != removed
        ]
    state_path.write_text(json.dumps(state), encoding="utf-8")
    print("service update accepted")
elif arguments[:3] == ["node", "ls", "--quiet"]:
    print("\n".join(state.get("nodes", {})))
elif arguments[:2] == ["node", "inspect"]:
    node = state.get("nodes", {}).get(arguments[2])
    if node is None:
        raise SystemExit(1)
    template = arguments[arguments.index("--format") + 1]
    match = re.search(r'index \.Spec\.Labels \\"([^\"]+)\\"', template)
    if match is None:
        match = re.search(r'index \.Spec\.Labels "([^\"]+)"', template)
    label_key = match.group(1)
    label_value = node.get("labels", {}).get(label_key, "<no value>")
    print(f'{node["state"]}|{node["availability"]}|{label_value}')
else:
    print(f"Unsupported fake Docker command: {arguments}", file=sys.stderr)
    raise SystemExit(2)
'''


def _run_reconciler(tmp_path: Path, state: dict, *arguments: str):
    """Run the reconciler against a stateful fake Docker CLI."""
    docker_path = tmp_path / "docker"
    docker_path.write_text(FAKE_DOCKER, encoding="utf-8")
    docker_path.chmod(0o755)

    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps(state), encoding="utf-8")
    log_path = tmp_path / "docker-calls.jsonl"

    environment = os.environ.copy()
    environment.update(
        {
            "FAKE_DOCKER_STATE": str(state_path),
            "FAKE_DOCKER_LOG": str(log_path),
            "PATH": f"{tmp_path}:{environment['PATH']}",
        }
    )
    result = subprocess.run(
        [str(RECONCILER), *arguments],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    calls = [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
    ]
    final_state = json.loads(state_path.read_text(encoding="utf-8"))
    return result, calls, final_state


def _node(
    *,
    state: str = "ready",
    availability: str = "active",
    labels: dict[str, str] | None = None,
) -> dict:
    """Build one fake Docker node inspection record."""
    return {
        "state": state,
        "availability": availability,
        "labels": labels or {},
    }


def _service_updates(calls: list[list[str]]) -> list[list[str]]:
    """Return only state-changing Docker service update calls."""
    return [call for call in calls if call[:2] == ["service", "update"]]


def test_adds_constraint_when_preferred_node_is_ready(tmp_path):
    """A healthy labeled node should receive the single monitor task."""
    result, calls, final_state = _run_reconciler(
        tmp_path,
        {
            "nodes": {
                "preferred": _node(labels={"internet-monitor": "true"}),
                "fallback": _node(),
            },
            "constraints": ["node.role==worker"],
        },
    )

    assert result.returncode == 0, result.stderr
    assert _service_updates(calls) == [
        [
            "service",
            "update",
            "--detach=true",
            "--constraint-add",
            "node.labels.internet-monitor==true",
            "internet-monitor_internet-monitor",
        ]
    ]
    assert "node.role==worker" in final_state["constraints"]
    assert "node.labels.internet-monitor==true" in final_state["constraints"]
    assert "ready preferred nodes: 1" in result.stdout


def test_removes_only_owned_constraint_when_preferred_node_is_down(tmp_path):
    """No healthy preferred node should leave unrelated constraints intact."""
    result, calls, final_state = _run_reconciler(
        tmp_path,
        {
            "nodes": {
                "preferred": _node(
                    state="down", labels={"internet-monitor": "true"}
                ),
                "fallback": _node(),
            },
            "constraints": [
                "node.role==worker",
                "node.labels.internet-monitor==true",
            ],
        },
    )

    assert result.returncode == 0, result.stderr
    updates = _service_updates(calls)
    assert len(updates) == 1
    assert updates[0][3:5] == [
        "--constraint-rm",
        "node.labels.internet-monitor==true",
    ]
    assert final_state["constraints"] == ["node.role==worker"]
    assert "no ready preferred node is available" in result.stdout


def test_does_not_update_an_already_correct_service(tmp_path):
    """Repeated timer runs must not restart or otherwise churn the service."""
    result, calls, _ = _run_reconciler(
        tmp_path,
        {
            "nodes": {
                "preferred": _node(labels={"internet-monitor": "true"})
            },
            "constraints": ["node.labels.internet-monitor == true"],
        },
    )

    assert result.returncode == 0, result.stderr
    assert _service_updates(calls) == []
    assert result.stdout == ""


def test_unlabeled_cluster_stays_schedulable_without_service_updates(tmp_path):
    """A new deployment must remain free to run before any node is labeled."""
    result, calls, _ = _run_reconciler(
        tmp_path,
        {"nodes": {"fallback": _node()}, "constraints": []},
    )

    assert result.returncode == 0, result.stderr
    assert _service_updates(calls) == []


def test_release_mode_removes_constraint_without_inspecting_nodes(tmp_path):
    """Uninstall should release placement even if the preferred node is ready."""
    result, calls, final_state = _run_reconciler(
        tmp_path,
        {
            "nodes": {
                "preferred": _node(labels={"internet-monitor": "true"})
            },
            "constraints": ["node.labels.internet-monitor == true"],
        },
        "--release-constraint",
    )

    assert result.returncode == 0, result.stderr
    assert not any(call[:2] == ["node", "ls"] for call in calls)
    assert final_state["constraints"] == []


def test_refuses_conflicting_constraint_for_managed_label(tmp_path):
    """The utility must not layer its rule over an operator-owned conflict."""
    result, calls, _ = _run_reconciler(
        tmp_path,
        {
            "nodes": {
                "preferred": _node(labels={"internet-monitor": "true"})
            },
            "constraints": ["node.labels.internet-monitor==false"],
        },
    )

    assert result.returncode == 1
    assert "different constraint" in result.stderr
    assert _service_updates(calls) == []


def test_refuses_to_run_outside_an_active_manager(tmp_path):
    """Worker nodes must never attempt to mutate Swarm service placement."""
    result, calls, _ = _run_reconciler(
        tmp_path,
        {"manager": False, "nodes": {}, "constraints": []},
    )

    assert result.returncode == 1
    assert "not an active Swarm manager" in result.stderr
    assert _service_updates(calls) == []


def test_refuses_a_manager_that_is_also_the_preferred_node(tmp_path):
    """The reconciler must survive the failure it is expected to handle."""
    result, calls, final_state = _run_reconciler(
        tmp_path,
        {
            "local_node_id": "preferred",
            "nodes": {
                "preferred": _node(labels={"internet-monitor": "true"}),
                "fallback": _node(),
            },
            "constraints": ["node.labels.internet-monitor==true"],
        },
    )

    assert result.returncode == 1
    assert "stable manager" in result.stderr
    assert len(_service_updates(calls)) == 1
    assert final_state["constraints"] == []


def test_systemd_unit_limits_privileges_and_serializes_runs():
    """The host utility should expose only the minimum practical interface."""
    service = (
        PROJECT_ROOT
        / "deploy"
        / "swarm-placement"
        / "internet-monitor-placement.service"
    ).read_text(encoding="utf-8")
    timer = (
        PROJECT_ROOT
        / "deploy"
        / "swarm-placement"
        / "internet-monitor-placement.timer"
    ).read_text(encoding="utf-8")

    assert "CapabilityBoundingSet=\n" in service
    assert "NoNewPrivileges=true" in service
    assert "PrivateNetwork=true" in service
    assert "ProtectSystem=strict" in service
    assert "RestrictAddressFamilies=AF_UNIX" in service
    assert "SystemCallArchitectures=native" in service
    assert "/usr/bin/flock --nonblock" in service
    assert "OnUnitActiveSec=30s" in timer
