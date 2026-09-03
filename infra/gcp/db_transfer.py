#!/usr/bin/env python3
"""Copy the local NDVM pgvector database to a provisioned Postgres pod."""

from __future__ import annotations

import argparse
import gzip
import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def run(args: list[str], *, capture: bool = False) -> str:
    print("+", " ".join(args))
    completed = subprocess.run(
        args, cwd=ROOT, check=True, text=True,
        stdout=subprocess.PIPE if capture else None,
    )
    return completed.stdout if capture else ""


def require(*commands: str) -> None:
    missing = [name for name in commands if shutil.which(name) is None]
    if missing:
        raise SystemExit(f"Missing required command(s): {', '.join(missing)}")


def backup(output: Path) -> None:
    require("podman")
    output.parent.mkdir(parents=True, exist_ok=True)
    dump = subprocess.Popen(
        [
            "podman-compose", "--env-file", ".env", "exec", "-T", "db", "pg_dump",
            "--clean", "--if-exists", "-U", os.environ.get("POSTGRES_USER", "ndvm"),
            "-d", os.environ.get("POSTGRES_DB", "ndvm"),
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
    )
    assert dump.stdout is not None
    with gzip.open(output, "wb") as archive:
        shutil.copyfileobj(dump.stdout, archive)
    if dump.wait() != 0:
        output.unlink(missing_ok=True)
        raise SystemExit("Local database backup failed.")
    print(f"Created {output}")


def replicas(namespace: str) -> str:
    return run([
        "kubectl", "-n", namespace, "get", "deployment/orchestrator",
        "-o", "jsonpath={.spec.replicas}",
    ], capture=True).strip() or "1"


def restore(source: Path, namespace: str) -> None:
    require("kubectl")
    if not source.is_file():
        raise SystemExit(f"Backup file does not exist: {source}")
    original_replicas = replicas(namespace)
    run(["kubectl", "-n", namespace, "scale", "deployment/orchestrator", "--replicas=0"])
    try:
        restore_process = subprocess.Popen(
            [
                "kubectl", "-n", namespace, "exec", "-i", "postgres-0", "--",
                "psql", "-v", "ON_ERROR_STOP=1",
                "-h", "127.0.0.1",
                "-U", os.environ.get("POSTGRES_USER", "ndvm"),
                "-d", os.environ.get("POSTGRES_DB", "ndvm"),
            ],
            stdin=subprocess.PIPE,
            cwd=ROOT,
        )
        assert restore_process.stdin is not None
        with gzip.open(source, "rb") as archive:
            shutil.copyfileobj(archive, restore_process.stdin)
        restore_process.stdin.close()
        if restore_process.wait() != 0:
            raise SystemExit("Postgres restore failed.")
    finally:
        run([
            "kubectl", "-n", namespace, "scale", "deployment/orchestrator",
            f"--replicas={original_replicas}",
        ])
    print(f"Restored {source} into {namespace}/postgres-0")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    backup_parser = commands.add_parser("backup", help="Create a compressed local database dump")
    backup_parser.add_argument("--output", type=Path, required=True)
    restore_parser = commands.add_parser("restore", help="Restore a dump into Postgres")
    restore_parser.add_argument("--input", type=Path, required=True)
    restore_parser.add_argument("--namespace", default=os.environ.get("K8S_NAMESPACE", "ndvm"))
    args = parser.parse_args()
    if args.action == "backup":
        backup(args.output)
    else:
        restore(args.input, args.namespace)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode)
