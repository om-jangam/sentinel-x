"""Operator CLI.

`sentinelx {generate-keys,migrate,seed,verify-audit,opensearch-init,load-demo,demo,pull-splunk,
evaluate-assistant,fetch-detection-datasets,evaluate-detection,worker,export-openapi}`
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
    # Permissions and system roles are defined in code and synced by `seed`, not by migrations.
    print("schema migrated; run `sentinelx seed` to sync permissions and system roles after an upgrade")
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


async def _load_demo(samples: Path, *, rebase: bool) -> int:
    import secrets

    from redis.asyncio import Redis
    from sqlalchemy import select

    from app.analysis import build_analysis
    from app.core.audit.port import AuditEvent
    from app.core.clock import utcnow
    from app.core.db.session import Database
    from app.core.events.bus import EventBus, InMemoryEventBus
    from app.core.events.redis_streams import RedisStreamsEventBus
    from app.core.events.topics import EVENTS_NORMALIZED, INCIDENTS_CHANGED
    from app.core.ids import uuid7
    from app.core.security.tokens import hash_opaque_token
    from app.modules.detection.infrastructure.rule_loader import load_rules
    from app.modules.detection.infrastructure.window_store import InMemoryWindowStore
    from app.modules.identity.infrastructure.models import OrgModel
    from app.modules.ingestion.application.indexing_service import IndexingService
    from app.modules.ingestion.application.ingest_service import IngestService
    from app.modules.ingestion.domain.entities import IngestSource
    from app.modules.ingestion.infrastructure.opensearch_store import event_store_from_settings
    from app.modules.ingestion.infrastructure.unit_of_work import SqlIngestionUnitOfWork
    from app.modules.threatintel.application.enrichment_service import EnrichmentService
    from app.modules.threatintel.domain.ports import IntelProvider
    from app.modules.threatintel.infrastructure.providers import providers_from_settings
    from app.modules.threatintel.infrastructure.repositories import sql_uow_factory as intel_uow_factory

    settings = get_settings()
    missing = [filename for _, _, filename, _ in SAMPLE_SOURCES if not (samples / filename).is_file()]
    if missing:
        print(f"sample telemetry not found in {samples}: {', '.join(missing)}", file=sys.stderr)
        return 1

    datasets = [
        (name, parser, description, _read_sample(samples / filename))
        for name, parser, filename, description in SAMPLE_SOURCES
    ]
    if rebase:
        # One shift for every file, so the attack story keeps its cross-source order and spacing.
        times = [t for *_, records in datasets for t in map(_sample_time, records) if t is not None]
        if times:
            delta = utcnow() - timedelta(minutes=5) - max(times)
            datasets = [(n, p, d, [_shift(r, delta) for r in records]) for n, p, d, records in datasets]

    store = event_store_from_settings(settings)
    database = Database(settings.database_url)
    redis = Redis.from_url(settings.redis_url) if settings.redis_url else None
    providers: list[IntelProvider] = []
    bus: EventBus
    if redis is not None:
        # The same path as live sources: the worker indexes, detects and correlates what is published.
        bus = RedisStreamsEventBus(redis)
    else:
        in_process = InMemoryEventBus()
        if store is not None:
            in_process.subscribe(EVENTS_NORMALIZED, IndexingService(store).handle)
        lookup = None if store is None else store.get_many
        analysis = build_analysis(
            load_rules(), database, InMemoryWindowStore(), lookup=lookup, publish=in_process.publish
        )
        in_process.subscribe(EVENTS_NORMALIZED, analysis.handle)
        providers = providers_from_settings(settings)
        if providers:
            enrichment = EnrichmentService(
                providers, uow_factory=intel_uow_factory(database), cache_ttl=timedelta(hours=settings.ti_cache_hours)
            )
            in_process.subscribe(INCIDENTS_CHANGED, enrichment.handle)
        bus = in_process
    if store is None:
        print(
            "warning: SENTINELX_OPENSEARCH_URL is not set, so the events are not stored or searchable; "
            "detection and correlation still run",
            file=sys.stderr,
        )
    try:
        if store is not None:
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
            existing = {source.name: source for source in await uow.sources.list_for_org(org.id)}

            for name, parser, description, records in datasets:
                source = existing.get(name)
                if source is not None and source.parser != parser:
                    print(f"source '{name}' already exists with parser '{source.parser}'", file=sys.stderr)
                    return 1
                if source is None:
                    source = IngestSource(
                        id=uuid7(),
                        org_id=org.id,
                        name=name,
                        description=description,
                        parser=parser,
                        is_enabled=True,
                        token_prefix="sxi_demo",  # noqa: S106 — a display prefix, not a credential
                        # Demo sources ingest in-process only: their credential is random and never revealed.
                        token_hash=hash_opaque_token(secrets.token_urlsafe(32)),
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
            if redis is not None:
                print("published to the event bus: the worker indexes, detects and correlates them")
            else:
                print("detection and correlation ran in-process")
    finally:
        if store is not None:
            await store.aclose()
        if redis is not None:
            await redis.aclose()
        for provider in providers:
            await provider.aclose()
        await database.dispose()
    return 0


def cmd_load_demo(args: argparse.Namespace) -> int:
    return asyncio.run(_load_demo(Path(args.samples), rebase=not args.keep_timestamps))


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


async def _evaluate_assistant() -> int:
    from app.assistant_eval import evaluate
    from app.modules.assistant.infrastructure.models_http import model_from_settings

    model = model_from_settings(get_settings())
    if model is None:
        print("set SENTINELX_AI_PROVIDER and SENTINELX_AI_MODEL to evaluate a model", file=sys.stderr)
        return 1
    try:
        results = await evaluate(model)
    finally:
        await model.aclose()

    def pct(value: float | None) -> str:
        return "  n/a" if value is None else f"{value:5.0%}"

    print(f"model {model.provider}/{model.model}")
    header = ("case", "status", "citations", "key events", "unsupported", "tech P", "tech R", "attrib")
    print(
        f"{header[0]:<24} {header[1]:<12} {header[2]:>9} {header[3]:>10} {header[4]:>11} {header[5]:>6} "
        f"{header[6]:>6} {header[7]:>8}"
    )
    for r in results:
        print(
            f"{r.case:<24} {r.status:<12} {pct(r.citation_validity):>9} {pct(r.key_event_recall):>10} "
            f"{pct(r.unsupported_rate):>11} {pct(r.technique_precision):>6} {pct(r.technique_recall):>6} "
            f"{r.unverified_attribution:>4}/{r.attribution_claims}"
        )
        for claim in r.detail.get("attribution", []):
            print(f"    attribution: {claim}")
        if r.missed_key_events:
            print(f"    missed: {', '.join(r.missed_key_events)}")
        if r.detail.get("reason"):
            print(f"    reason: {r.detail['reason']}")
    passed = all(r.passed for r in results)
    print("PASS: every citation was valid" if passed else "FAIL: citation validity must be 100% on every case")
    return 0 if passed else 1


def cmd_demo(args: argparse.Namespace) -> int:
    from app.demo import run_demo

    password = os.environ.get("SENTINELX_DEMO_PASSWORD") or getpass.getpass(f"Password for {args.email}: ")
    return run_demo(args.api_url, args.email, password, Path(args.samples), analyse=args.analyse)


def cmd_evaluate_assistant(_: argparse.Namespace) -> int:
    return asyncio.run(_evaluate_assistant())


def cmd_pull_splunk(args: argparse.Namespace) -> int:
    """Search a Splunk server and ingest what it returns. Both tokens come from the environment."""
    import httpx

    from app.core.config import get_settings
    from app.splunk_collector import SplunkError, pull, splunk_client

    settings = get_settings()
    url = args.splunk_url or settings.splunk_url
    token = os.environ.get("SENTINELX_SPLUNK_TOKEN") or (
        settings.splunk_token.get_secret_value() if settings.splunk_token else None
    )
    ingest_token = os.environ.get("SENTINELX_INGEST_TOKEN")
    if not url or not token:
        print("set SENTINELX_SPLUNK_URL and SENTINELX_SPLUNK_TOKEN", file=sys.stderr)
        return 2
    if not ingest_token:
        print(
            "set SENTINELX_INGEST_TOKEN to the token of the ingest source these events belong to "
            "(POST /api/v1/ingest/sources returns it once)",
            file=sys.stderr,
        )
        return 2

    print(f"searching {url} for {args.earliest} .. {args.latest}")
    splunk = splunk_client(url, token, verify=settings.splunk_verify_certs, timeout=settings.splunk_timeout_seconds)
    api = httpx.Client(base_url=args.api_url.rstrip("/"), timeout=httpx.Timeout(60.0))
    try:
        outcome = pull(
            splunk,
            api,
            search=args.search,
            earliest=args.earliest,
            latest=args.latest,
            ingest_token=ingest_token,
            parser=args.parser,
            limit=args.limit,
        )
    except SplunkError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        splunk.close()
        api.close()

    print(f"{outcome.results} results, {outcome.mapped} for parser '{args.parser}'")
    print(f"ingested: accepted {outcome.accepted}, rejected {outcome.rejected}")
    for reason, count in sorted(outcome.unmapped.items(), key=lambda item: -item[1])[:10]:
        print(f"  not sent ({count}): {reason}")
    for reason in outcome.ingest_errors:
        print(f"  rejected: {reason}")
    return 0


def cmd_fetch_detection_datasets(args: argparse.Namespace) -> int:
    from app.detection_eval import DATASETS, DatasetIntegrityError, fetch

    total = sum(file.size for dataset in DATASETS for file in dataset.files)
    print(f"{len(DATASETS)} recordings, {total / 1_000_000:.1f} MB from splunk/attack_data into {args.cache}")
    try:
        outcomes = asyncio.run(fetch(DATASETS, Path(args.cache)))
    except DatasetIntegrityError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    for file, outcome in outcomes:
        print(f"{outcome:>10}  {file.path}")
    return 0


def cmd_evaluate_detection(args: argparse.Namespace) -> int:
    from app.detection_eval import DATASETS, evaluate, render_report
    from app.modules.detection.infrastructure.rule_loader import load_rules

    try:
        results = asyncio.run(evaluate(DATASETS, Path(args.cache)))
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    report = render_report(results, rule_count=len(load_rules().all()), generated=datetime.now().astimezone())
    if args.report:
        Path(args.report).write_text(report, encoding="utf-8")
        print(f"report written to {args.report}")
    for result in results:
        mark = "detected" if result.detected else "missed"
        print(f"{result.dataset.technique:<10} {mark:<9} parsed {result.accepted:>6,} of {result.events:>6,} events")
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
    demo.add_argument(
        "--samples",
        default=str(BACKEND_ROOT.parent / "pipeline" / "samples"),
        help="directory holding the sample files (mount pipeline/samples when running in a container)",
    )
    demo.set_defaults(func=cmd_load_demo)

    demo_run = sub.add_parser("demo", help="run the end-to-end demo against a running deployment, over HTTP")
    demo_run.add_argument("--api-url", default="http://localhost:8080", help="the console/API origin")
    demo_run.add_argument("--email", default="admin@example.com")
    demo_run.add_argument("--samples", default=str(BACKEND_ROOT.parent / "pipeline" / "samples"))
    demo_run.add_argument("--analyse", action="store_true", help="also ask the AI assistant (slow with local models)")
    demo_run.set_defaults(func=cmd_demo)

    sub.add_parser(
        "evaluate-assistant", help="score the configured AI model on the labelled sample incidents"
    ).set_defaults(func=cmd_evaluate_assistant)

    splunk = sub.add_parser("pull-splunk", help="search a Splunk server and ingest the results")
    splunk.add_argument(
        "--search", required=True, help="the Splunk search, e.g. index=windows sourcetype=XmlWinEventLog*"
    )
    splunk.add_argument("--parser", required=True, help="the ingest source's parser; other sourcetypes are skipped")
    splunk.add_argument("--earliest", default="-24h", help="Splunk earliest_time (default -24h)")
    splunk.add_argument("--latest", default="now", help="Splunk latest_time (default now)")
    splunk.add_argument("--limit", type=int, default=10_000, help="maximum results to pull (default 10000)")
    splunk.add_argument("--api-url", default="http://localhost:8080", help="the Sentinel-X API")
    splunk.add_argument("--splunk-url", help="overrides SENTINELX_SPLUNK_URL")
    splunk.set_defaults(func=cmd_pull_splunk)

    # Kept in step with app.detection_eval.DEFAULT_CACHE (not imported here, so `--help` stays light).
    dataset_cache = str(BACKEND_ROOT / ".cache" / "detection-datasets")

    fetch_datasets = sub.add_parser(
        "fetch-detection-datasets", help="download the public attack recordings (verified by SHA-256)"
    )
    fetch_datasets.add_argument("--cache", default=dataset_cache)
    fetch_datasets.set_defaults(func=cmd_fetch_detection_datasets)

    evaluate_detection = sub.add_parser(
        "evaluate-detection", help="replay the public attack recordings through the shipped rules"
    )
    evaluate_detection.add_argument("--cache", default=dataset_cache)
    evaluate_detection.add_argument("--report", help="write the Markdown report here")
    evaluate_detection.set_defaults(func=cmd_evaluate_detection)

    openapi = sub.add_parser("export-openapi", help="write the OpenAPI document")
    openapi.add_argument("--out", default=str(BACKEND_ROOT / "openapi.json"))
    openapi.set_defaults(func=cmd_export_openapi)

    args = parser.parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
