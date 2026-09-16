"""Operator CLI.

`sentinelx {generate-keys,migrate,seed,verify-audit,opensearch-init,load-demo,worker,export-openapi}`
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import os
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

from app.core.config import get_settings

BACKEND_ROOT = Path(__file__).resolve().parent.parent


def _alembic_config() -> object:
    from alembic.config import Config

    # Resolved from the installed package, so `sentinelx migrate` also works inside the container image.
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).resolve().parent / "migrations"))
    return config


def cmd_generate_keys(args: argparse.Namespace) -> int:
    from app.core.security.keys import (
        generate_private_key,
        jwk_thumbprint,
        private_key_to_pem,
        public_key_to_pem,
    )

    out = Path(args.out)
    private_path, public_path = out / "jwt_private.pem", out / "jwt_public.pem"
    if private_path.exists() and not args.force:
        print(f"{private_path} exists; pass --force to rotate", file=sys.stderr)
        return 1
    out.mkdir(parents=True, exist_ok=True)
    if private_path.exists():
        # Keep the outgoing public key so tokens it signed stay verifiable during rotation.
        previous = out / "jwt_previous_public.pem"
        previous.write_bytes(public_path.read_bytes())
        print(f"previous public key kept at {previous} (set SENTINELX_JWT_PREVIOUS_PUBLIC_KEY_FILE)")
    key = generate_private_key()
    private_path.write_bytes(private_key_to_pem(key))
    if os.name == "posix":
        private_path.chmod(0o600)
    public_path.write_bytes(public_key_to_pem(key.public_key()))
    print(f"wrote {private_path} (kid={jwk_thumbprint(key.public_key())})")
    return 0


def cmd_migrate(args: argparse.Namespace) -> int:
    from alembic import command

    command.upgrade(_alembic_config(), args.revision)  # type: ignore[arg-type]
    return 0


async def _seed(args: argparse.Namespace, password: str | None) -> int:
    from app.core.db.session import Database
    from app.core.errors import AppError
    from app.core.security.passwords import PasswordHasher
    from app.modules.identity.application.bootstrap import bootstrap_platform, create_initial_admin
    from app.modules.identity.infrastructure.unit_of_work import SqlIdentityUnitOfWork

    settings = get_settings()
    database = Database(settings.database_url)
    try:
        async with database.sessionmaker() as session:
            uow = SqlIdentityUnitOfWork(session)
            result = await bootstrap_platform(uow, org_name=args.org_name, org_slug=args.org_slug)
            print(
                f"org '{result.org.slug}' {'created' if result.org_created else 'exists'}; "
                f"roles created={result.roles_created} updated={result.roles_updated}"
            )
            if args.admin_email:
                if await uow.users.get_by_email(args.admin_email.strip().lower()) is not None:
                    print(f"admin {args.admin_email} already exists; skipped")
                    return 0
                if password is None:
                    print("an admin password is required", file=sys.stderr)
                    return 1
                hasher = PasswordHasher(
                    time_cost=settings.argon2_time_cost,
                    memory_cost_kib=settings.argon2_memory_cost_kib,
                    parallelism=settings.argon2_parallelism,
                )
                try:
                    user = await create_initial_admin(
                        uow,
                        hasher,
                        org=result.org,
                        email=args.admin_email,
                        full_name=args.admin_name,
                        password=password,
                    )
                except AppError as exc:
                    details = "; ".join(e.get("msg", "") for e in exc.errors)
                    print(f"error: {exc.detail}{': ' + details if details else ''}", file=sys.stderr)
                    return 1
                print(f"created admin {user.email}")
    finally:
        await database.dispose()
    return 0


def cmd_seed(args: argparse.Namespace) -> int:
    password = os.environ.get("SENTINELX_BOOTSTRAP_ADMIN_PASSWORD")
    if args.admin_email and password is None and sys.stdin.isatty():
        password = getpass.getpass("Admin password: ")
        if getpass.getpass("Repeat password: ") != password:
            print("passwords do not match", file=sys.stderr)
            return 1
    return asyncio.run(_seed(args, password))


async def _verify_audit(org_id: str | None) -> int:
    from uuid import UUID

    from app.core.audit.repository import list_audited_org_ids, verify_audit_chain
    from app.core.db.session import Database

    database = Database(get_settings().database_url)
    failures = 0
    try:
        async with database.sessionmaker() as session:
            org_ids = [UUID(org_id)] if org_id else await list_audited_org_ids(session)
            for oid in org_ids:
                result = await verify_audit_chain(session, oid)
                failures += 0 if result.valid else 1
                print(
                    json.dumps(
                        {
                            "org_id": str(result.org_id),
                            "valid": result.valid,
                            "entries_checked": result.entries_checked,
                            "head_hash": result.head_hash,
                            "broken_at_index": result.broken_at_index,
                            "reason": result.reason,
                        }
                    )
                )
    finally:
        await database.dispose()
    return 1 if failures else 0


def cmd_verify_audit(args: argparse.Namespace) -> int:
    return asyncio.run(_verify_audit(args.org_id))


SAMPLE_SOURCES = (
    ("demo-linux-auth", "linux_auth", "linux_auth.log", "sshd on web-01"),
    ("demo-windows-security", "windows_security", "windows_security.jsonl", "Security log from WS-FIN-07"),
    ("demo-network", "ocsf", "ocsf_network.jsonl", "Zeek conn/dns from the core switch"),
)
_RFC3339_PREFIX = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})")


def _read_sample(path: Path) -> list[dict[str, object]]:
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if path.suffix == ".jsonl":
        return [json.loads(line) for line in lines]
    return [{"message": line} for line in lines]


def _sample_time(record: dict[str, object]) -> datetime | None:
    from app.ingest_pipeline.ocsf import parse_event_time

    if "time" in record:
        return parse_event_time(record["time"])
    if (value := record.get("TimeCreated")) is not None:
        return parse_event_time(value)
    match = _RFC3339_PREFIX.match(str(record.get("message", "")))
    return parse_event_time(match.group(0)) if match else None


def _shift(record: dict[str, object], delta: timedelta) -> dict[str, object]:
    """Move demo telemetry into the recent past so it lands inside default search windows."""
    shifted = dict(record)
    original = _sample_time(record)
    if original is None:
        return shifted
    moved = original + delta
    if "time" in shifted:
        shifted["time"] = moved.isoformat()
    elif "TimeCreated" in shifted:
        shifted["TimeCreated"] = moved.isoformat()
    else:
        message = str(shifted.get("message", ""))
        shifted["message"] = _RFC3339_PREFIX.sub(moved.isoformat(), message, count=1)
    return shifted


async def _load_demo(rebase: bool) -> int:
    from sqlalchemy import select

    from app.core.audit.port import AuditEvent
    from app.core.clock import utcnow
    from app.core.db.session import Database
    from app.core.events.bus import InMemoryEventBus
    from app.core.events.topics import EVENTS_NORMALIZED
    from app.core.ids import uuid7
    from app.core.security.tokens import hash_opaque_token
    from app.modules.identity.infrastructure.models import OrgModel
    from app.modules.ingestion.application.indexing_service import IndexingService
    from app.modules.ingestion.application.ingest_service import IngestService
    from app.modules.ingestion.domain.entities import IngestSource
    from app.modules.ingestion.infrastructure.opensearch_store import event_store_from_settings
    from app.modules.ingestion.infrastructure.unit_of_work import SqlIngestionUnitOfWork

    settings = get_settings()
    samples = BACKEND_ROOT.parent / "pipeline" / "samples"
    if not samples.is_dir():
        print(f"sample telemetry not found at {samples}", file=sys.stderr)
        return 1

    store = event_store_from_settings(settings)
    if store is None:
        print("set SENTINELX_OPENSEARCH_URL before loading demo telemetry", file=sys.stderr)
        return 1

    bus = InMemoryEventBus()
    bus.subscribe(EVENTS_NORMALIZED, IndexingService(store).handle)
    database = Database(settings.database_url)
    try:
        await store.ensure_ready()
        async with database.sessionmaker() as session:
            org = await session.scalar(select(OrgModel).order_by(OrgModel.created_at))
            if org is None:
                print("no organisation found; run `sentinelx seed` first", file=sys.stderr)
                return 1

            uow = SqlIngestionUnitOfWork(session)
            service = IngestService(uow, bus=bus)
            now = utcnow()
            total_accepted = total_rejected = 0

            for name, parser, filename, description in SAMPLE_SOURCES:
                records = _read_sample(samples / filename)
                if rebase:
                    newest = max((t for t in map(_sample_time, records) if t is not None), default=None)
                    if newest is not None:
                        records = [_shift(record, now - timedelta(minutes=5) - newest) for record in records]

                source = await uow.sources.get_by_token_hash(hash_opaque_token(f"demo:{org.id}:{name}"))
                if source is None:
                    source = IngestSource(
                        id=uuid7(),
                        org_id=org.id,
                        name=name,
                        description=description,
                        parser=parser,
                        is_enabled=True,
                        token_prefix="sxi_demo",  # noqa: S106 — a display prefix, not a credential
                        token_hash=hash_opaque_token(f"demo:{org.id}:{name}"),
                        created_at=now,
                        updated_at=now,
                    )
                    await uow.sources.add(source)
                    await uow.audit.record(
                        AuditEvent(
                            org_id=org.id,
                            action="ingest_source.created",
                            resource_type="ingest_source",
                            resource_id=str(source.id),
                            actor_type="system",
                            after=source.audit_view(),
                            context={"via": "load-demo"},
                        )
                    )
                    await uow.commit()

                result = await service.ingest(source=source, records=records)
                total_accepted += result.accepted
                total_rejected += result.rejected
                print(f"{name}: accepted {result.accepted}, rejected {result.rejected}")

            print(f"loaded {total_accepted} events ({total_rejected} records skipped)")
    finally:
        await store.aclose()
        await database.dispose()
    return 0


def cmd_load_demo(args: argparse.Namespace) -> int:
    return asyncio.run(_load_demo(rebase=not args.keep_timestamps))


def cmd_worker(_: argparse.Namespace) -> int:
    from app.worker import main as worker_main

    return worker_main()


async def _opensearch_init() -> int:
    from app.modules.ingestion.infrastructure.opensearch_store import event_store_from_settings

    store = event_store_from_settings(get_settings())
    if store is None:
        print("set SENTINELX_OPENSEARCH_URL first", file=sys.stderr)
        return 1
    try:
        await store.ensure_ready()
        print("event store templates and lifecycle policy applied")
    finally:
        await store.aclose()
    return 0


def cmd_opensearch_init(_: argparse.Namespace) -> int:
    return asyncio.run(_opensearch_init())


def cmd_export_openapi(args: argparse.Namespace) -> int:
    from app.core.config import Environment, Settings
    from app.main import create_app

    app = create_app(Settings(environment=Environment.TEST, database_url="sqlite+aiosqlite://"))
    Path(args.out).write_text(json.dumps(app.openapi(), indent=2) + "\n", encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinelx")
    sub = parser.add_subparsers(dest="command", required=True)

    keys = sub.add_parser("generate-keys", help="create an RS256 signing key pair")
    keys.add_argument("--out", default=str(BACKEND_ROOT.parent / ".secrets"))
    keys.add_argument("--force", action="store_true", help="rotate an existing key")
    keys.set_defaults(func=cmd_generate_keys)

    migrate = sub.add_parser("migrate", help="apply database migrations")
    migrate.add_argument("revision", nargs="?", default="head")
    migrate.set_defaults(func=cmd_migrate)

    seed = sub.add_parser("seed", help="bootstrap org, permissions, system roles and first admin")
    seed.add_argument("--org-name", default="Sentinel-X")
    seed.add_argument("--org-slug", default="default")
    seed.add_argument("--admin-email")
    seed.add_argument("--admin-name", default="Platform Administrator")
    seed.set_defaults(func=cmd_seed)

    verify = sub.add_parser("verify-audit", help="verify the audit hash chain (exit 1 if broken)")
    verify.add_argument("--org-id")
    verify.set_defaults(func=cmd_verify_audit)

    sub.add_parser("worker", help="run the indexer worker (needs Redis and OpenSearch)").set_defaults(func=cmd_worker)

    sub.add_parser("opensearch-init", help="apply event index templates and lifecycle policy").set_defaults(
        func=cmd_opensearch_init
    )

    demo = sub.add_parser("load-demo", help="ingest the shipped demo telemetry")
    demo.add_argument(
        "--keep-timestamps",
        action="store_true",
        help="load the samples at their original dates instead of shifting them to now",
    )
    demo.set_defaults(func=cmd_load_demo)

    openapi = sub.add_parser("export-openapi", help="write the OpenAPI document")
    openapi.add_argument("--out", default=str(BACKEND_ROOT / "openapi.json"))
    openapi.set_defaults(func=cmd_export_openapi)

    args = parser.parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
