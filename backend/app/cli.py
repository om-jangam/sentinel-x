"""Operator CLI: `sentinelx {generate-keys,migrate,seed,verify-audit,export-openapi}`."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import os
import sys
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

    openapi = sub.add_parser("export-openapi", help="write the OpenAPI document")
    openapi.add_argument("--out", default=str(BACKEND_ROOT / "openapi.json"))
    openapi.set_defaults(func=cmd_export_openapi)

    args = parser.parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
