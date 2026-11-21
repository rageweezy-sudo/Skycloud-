import hashlib
import os
import secrets
import sys
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from importlib.resources import files
from itertools import groupby
from pathlib import Path
from threading import RLock
from uuid import uuid4

from .credentials import CredentialError, CredentialVault, WindowsCredentialVault
from .domains import normalize_origin, registrable_domain
from .local_files import local_path
from .models import Account, Evidence, EvidenceCategory, Provider, RequestEvent, RequestRecord, ReviewState, Service, ServiceAccount
from .scoring import Confidence, score_evidence


class StorageError(RuntimeError):
    pass


class ScanConflict(StorageError):
    pass


@dataclass(frozen=True, slots=True)
class InventoryEntry:
    service_account: ServiceAccount
    confidence: Confidence
    evidence_count: int
    sources: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ScanRun:
    id: str
    account_id: str
    source: str
    selection: str
    cursor: str | None = None
    revision: int = 0
    processed: int = 0
    complete: bool = False


def _load_driver():
    from sqlcipher3 import dbapi2

    return dbapi2


@contextmanager
def _initialization_lock(path: Path) -> Iterator[None]:
    # Keep the lock file in place so simultaneous opens always lock the same file.
    with path.with_suffix(path.suffix + ".init-lock").open("a+b") as lock:
        if sys.platform == "win32":
            import msvcrt

            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        yield


def open_storage(path: Path, vault: CredentialVault | None = None) -> "Storage":
    """Open an encrypted database, failing closed if the cipher or vault fails."""
    try:
        driver = _load_driver()
    except (ImportError, OSError):
        raise StorageError("SQLCipher is unavailable") from None

    probe = None
    try:
        probe = driver.connect(":memory:")
        result = probe.execute("PRAGMA cipher_version").fetchone()
        if not result or not result[0]:
            raise StorageError("The database driver does not provide SQLCipher")
    except (driver.Error, AttributeError):
        raise StorageError("Could not initialize SQLCipher") from None
    finally:
        if probe is not None:
            probe.close()

    connection = None
    try:
        if vault is None:
            vault = WindowsCredentialVault()
        path = local_path(path).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        reference = "database/" + hashlib.sha256(os.path.normcase(str(path)).encode("utf-8")).hexdigest()
        with _initialization_lock(path):
            key = vault.read(reference)
            exists = path.exists()
            if key is None:
                if exists:
                    raise StorageError("The database key is missing from Windows Credential Manager")
                key = secrets.token_bytes(32)
                vault.write(reference, key)
            if len(key) != 32:
                raise StorageError("The stored database key is invalid")

            mode = "rw" if exists else "rwc"
            connection = driver.connect(
                f"{path.as_uri()}?mode={mode}", uri=True, isolation_level=None, check_same_thread=False
            )
            connection.execute(f"""PRAGMA key = "x'{key.hex()}'" """)
            connection.execute("PRAGMA cipher_plaintext_header_size = 0")
            connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
            return Storage(connection)
    except BaseException as error:
        if connection is not None:
            connection.close()
        if isinstance(error, (CredentialError, OSError, driver.Error)):
            raise StorageError("Could not open the encrypted database or access its credential") from None
        raise


class Storage:
    """Serialize database transactions for the application and its workers."""

    def __init__(self, connection) -> None:
        self._db = connection
        self._lock = RLock()
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.execute("PRAGMA temp_store = MEMORY")
        self._migrate()

    def _migrate(self) -> None:
        directory = files("account_privacy").joinpath("core", "migrations")
        migrations = sorted((path for path in directory.iterdir() if path.name.endswith(".sql")), key=lambda path: path.name)
        version = self._db.execute("PRAGMA user_version").fetchone()[0]
        if not migrations or version > len(migrations):
            raise StorageError("The database schema is unsupported")
        for number, migration in enumerate(migrations, start=1):
            if not migration.name.startswith(f"{number:03d}_"):
                raise StorageError("The database migrations are incomplete")
            if number > version:
                try:
                    sql = migration.read_text(encoding="utf-8")
                    self._db.executescript(f"BEGIN IMMEDIATE;\n{sql}\nPRAGMA user_version = {number};\nCOMMIT;")
                except BaseException:
                    self._db.rollback()
                    raise

    def close(self) -> None:
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self._db.commit()
            except BaseException:
                self._db.rollback()
                raise

    def save_account(self, account: Account) -> None:
        with self._transaction():
            cursor = self._db.execute(
                """INSERT INTO accounts (id, email, provider, credential_ref) VALUES (?, ?, ?, ?)
                   ON CONFLICT (id) DO UPDATE SET credential_ref = excluded.credential_ref
                   WHERE accounts.email = excluded.email AND accounts.provider = excluded.provider""",
                (account.id, account.email, account.provider, account.credential_ref),
            )
            if cursor.rowcount != 1:
                raise StorageError("Cannot change a stored account's identity")

    def list_accounts(self) -> list[Account]:
        with self._lock:
            rows = self._db.execute("SELECT id, email, provider, credential_ref FROM accounts ORDER BY id")
            return [Account(row[0], row[1], Provider(row[2]), row[3]) for row in rows]

    def _add_evidence(self, entry: Evidence) -> None:
        record = entry.service_account
        domain = registrable_domain(record.service.domain)
        origin = normalize_origin(record.origin) if record.origin is not None else None
        self._db.execute("INSERT INTO services VALUES (?) ON CONFLICT DO NOTHING", (domain,))
        self._db.execute(
            """INSERT INTO service_accounts (domain, account_id, username, origin) VALUES (?, ?, ?, ?)
               ON CONFLICT (domain, account_id, username)
               DO UPDATE SET origin = COALESCE(service_accounts.origin, excluded.origin)""",
            (domain, record.account_id, record.username, origin),
        )
        timestamp = entry.observed_at
        if timestamp is not None:
            if timestamp.utcoffset() is None:
                raise StorageError("Evidence timestamps require a timezone")
            timestamp = timestamp.astimezone(UTC).isoformat()
        self._db.execute(
            """INSERT INTO evidence (service_account_id, source, item_id, category, observed_at, ambiguous)
               SELECT id, ?, ?, ?, ?, ?
               FROM service_accounts WHERE domain = ? AND account_id = ? AND username = ?
               ON CONFLICT (service_account_id, source, item_id, category)
               DO UPDATE SET ambiguous = min(evidence.ambiguous, excluded.ambiguous)""",
            (entry.source, entry.item_id, entry.category, timestamp, entry.ambiguous, domain, record.account_id, record.username),
        )

    def add_evidence(self, entries: Iterable[Evidence]) -> None:
        with self._transaction():
            for entry in entries:
                self._add_evidence(entry)

    def set_review(self, record: ServiceAccount, review: ReviewState) -> None:
        with self._transaction():
            cursor = self._db.execute(
                "UPDATE service_accounts SET review = ? WHERE domain = ? AND account_id = ? AND username = ?",
                (review, registrable_domain(record.service.domain), record.account_id, record.username),
            )
            if cursor.rowcount != 1:
                raise StorageError("The service account no longer exists")

    def inventory(self) -> list[InventoryEntry]:
        with self._lock:
            rows = self._db.execute(
                """SELECT service_accounts.id, domain, account_id, username, origin, review,
                          category, count(*), min(ambiguous), group_concat(DISTINCT source)
                   FROM service_accounts JOIN evidence ON service_account_id = service_accounts.id
                   GROUP BY service_accounts.id, category
                   ORDER BY domain, account_id, username, category"""
            )
            inventory = []
            for _, group in groupby(rows, key=lambda row: row[0]):
                categories = list(group)
                _, domain, account, username, origin, review, *_ = categories[0]
                attributed = [EvidenceCategory(row[6]) for row in categories if not row[8]]
                confidence = (
                    score_evidence(attributed)
                    if attributed
                    else score_evidence((EvidenceCategory(row[6]) for row in categories), ambiguous=True)
                )
                record = ServiceAccount(Service(domain), account, username, origin, ReviewState(review))
                sources = tuple(sorted({source for row in categories for source in row[9].split(",")}))
                inventory.append(InventoryEntry(record, confidence, sum(row[7] for row in categories), sources))
            return inventory

    def create_scan(self, account_id: str, source: str, selection: str) -> ScanRun:
        run = ScanRun(uuid4().hex, account_id, source, selection)
        with self._transaction():
            self._db.execute("INSERT INTO scan_runs VALUES (?, ?, ?, ?)", (run.id, account_id, source, selection))
            self._db.execute("INSERT INTO scan_checkpoints (run_id) VALUES (?)", (run.id,))
        return run

    def get_scan(self, run_id: str) -> ScanRun:
        with self._lock:
            row = self._db.execute(
                """SELECT id, account_id, source, selection, cursor, revision, processed, complete
                   FROM scan_runs JOIN scan_checkpoints ON run_id = id
                   WHERE id = ?""",
                (run_id,),
            ).fetchone()
        if row is None:
            raise StorageError("The scan no longer exists")
        return ScanRun(*row[:-1], complete=bool(row[-1]))

    def commit_page(
        self, run_id: str, revision: int, entries: Iterable[Evidence],
        cursor: str | None, processed: int, *, complete: bool = False,
    ) -> ScanRun:
        if processed < 0:
            raise StorageError("Page progress cannot be negative")
        with self._transaction():
            run = self.get_scan(run_id)
            if run.complete or run.revision != revision:
                raise ScanConflict("The scan checkpoint has changed")
            for entry in entries:
                if entry.service_account.account_id != run.account_id or entry.source != run.source:
                    raise StorageError("Evidence does not belong to this scan")
                self._add_evidence(entry)
            self._db.execute(
                """UPDATE scan_checkpoints SET cursor = ?, revision = revision + 1,
                   processed = processed + ?, complete = ? WHERE run_id = ?""",
                (cursor, processed, complete, run_id),
            )
            return self.get_scan(run_id)

    def restart_scan(self, run_id: str, revision: int) -> ScanRun:
        with self._transaction():
            cursor = self._db.execute(
                """UPDATE scan_checkpoints SET cursor = NULL, processed = 0, revision = revision + 1
                   WHERE run_id = ? AND revision = ? AND complete = 0""",
                (run_id, revision),
            )
            if cursor.rowcount != 1:
                raise ScanConflict("The scan checkpoint has changed")
            return self.get_scan(run_id)

    def latest_scan(self, account_id: str, source: str, selection: str, *, complete: bool) -> ScanRun | None:
        with self._lock:
            row = self._db.execute(
                """SELECT id FROM scan_runs JOIN scan_checkpoints ON run_id = id
                   WHERE account_id = ? AND source = ? AND selection = ? AND complete = ?
                   ORDER BY scan_runs.rowid DESC LIMIT 1""",
                (account_id, source, selection, complete),
            ).fetchone()
            return self.get_scan(row[0]) if row else None

    def scan_history(self) -> list[ScanRun]:
        with self._lock:
            rows = self._db.execute("SELECT id FROM scan_runs ORDER BY rowid DESC").fetchall()
            return [self.get_scan(row[0]) for row in rows]

    def reserve_request(
        self, record: ServiceAccount, kind: str, jurisdiction: str, version: int,
        destination_kind: str, destination: str, now: datetime, parent_id: str | None,
    ) -> RequestRecord:
        request_id = uuid4().hex
        state = "pending" if destination_kind == "email" else "portal_pending"
        now = now.astimezone(UTC)
        with self._transaction():
            row = self._db.execute(
                "SELECT id FROM service_accounts WHERE domain = ? AND account_id = ? AND username = ?",
                (record.service.domain, record.account_id, record.username),
            ).fetchone()
            if row is None:
                raise StorageError("The service account no longer exists")
            service_id = row[0]
            if parent_id is not None:
                parent = self.get_request(parent_id)
                if parent.sent_at is None or (
                    parent.service_account.service, parent.service_account.account_id, parent.service_account.username
                ) != (record.service, record.account_id, record.username):
                    raise StorageError("The original request belongs to a different service account")
            if state == "pending":
                unresolved = self._db.execute(
                    """SELECT 1 FROM requests WHERE service_account_id = ? AND kind = ?
                       AND state IN ('pending', 'uncertain') LIMIT 1""",
                    (service_id, kind),
                ).fetchone()
                if unresolved:
                    raise StorageError("Reconcile the previous submission before trying again")
                last_day = (now - timedelta(days=1)).isoformat()
                count, latest = self._db.execute(
                    """SELECT count(*), max(created_at) FROM requests
                       JOIN service_accounts ON service_accounts.id = requests.service_account_id
                       WHERE account_id = ? AND destination_kind = 'email' AND created_at > ?""",
                    (record.account_id, last_day),
                ).fetchone()
                if count >= 25 or (latest and datetime.fromisoformat(latest) + timedelta(seconds=30) > now):
                    raise StorageError("This account reached its sending limit. Wait before trying again.")
            self._db.execute(
                """INSERT INTO requests(id, service_account_id, kind, jurisdiction, template_version,
                                        destination_kind, destination, state, created_at, parent_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (request_id, service_id, kind, jurisdiction, version, destination_kind, destination, state, now.isoformat(), parent_id),
            )
            self._record_event(request_id, state, now)
            return self.get_request(request_id)

    def _record_event(self, request_id: str, kind: str, now: datetime, item_id: str | None = None) -> None:
        self._db.execute(
            "INSERT INTO request_events (request_id, kind, timestamp, item_id) VALUES (?, ?, ?, ?)",
            (request_id, kind, now.astimezone(UTC).isoformat(), item_id),
        )

    def get_request(self, request_id: str) -> RequestRecord:
        records = self._read_requests("WHERE requests.id = ?", (request_id,))
        if not records:
            raise StorageError("The request no longer exists")
        return records[0]

    def list_requests(self) -> list[RequestRecord]:
        return self._read_requests("", ())

    def _read_requests(self, where: str, params: tuple) -> list[RequestRecord]:
        with self._lock:
            rows = self._db.execute(
                """SELECT requests.id, domain, account_id, username, origin, review,
                          kind, jurisdiction, destination_kind, destination, state, created_at,
                          sent_at, message_id, thread_id, adjusted_due, parent_id
                   FROM requests JOIN service_accounts ON service_account_id = service_accounts.id """
                + where + " ORDER BY created_at DESC, requests.id",
                params,
            )
            return [
                RequestRecord(
                    row[0], ServiceAccount(Service(row[1]), row[2], row[3], row[4], ReviewState(row[5])),
                    *row[6:11], datetime.fromisoformat(row[11]), datetime.fromisoformat(row[12]) if row[12] else None,
                    *row[13:],
                )
                for row in rows
            ]

    def request_events(self, request_id: str) -> list[RequestEvent]:
        with self._lock:
            rows = self._db.execute(
                "SELECT kind, timestamp FROM request_events WHERE request_id = ? ORDER BY id", (request_id,)
            )
            return [RequestEvent(kind, datetime.fromisoformat(timestamp)) for kind, timestamp in rows]

    def finish_request(
        self, request_id: str, expected: str, state: str, now: datetime,
        message_id: str | None = None, thread_id: str | None = None,
    ) -> RequestRecord:
        sent_at = now.astimezone(UTC).isoformat() if state == "sent" else None
        with self._transaction():
            cursor = self._db.execute(
                """UPDATE requests SET state = ?, sent_at = coalesce(?, sent_at),
                   message_id = coalesce(?, message_id), thread_id = coalesce(?, thread_id)
                   WHERE id = ? AND state = ?""",
                (state, sent_at, message_id, thread_id, request_id, expected),
            )
            if cursor.rowcount != 1:
                raise StorageError("The request's status changed")
            self._record_event(request_id, state, now)
            return self.get_request(request_id)

    def adjust_request_deadline(self, request_id: str, due, now: datetime) -> RequestRecord:
        with self._transaction():
            cursor = self._db.execute(
                "UPDATE requests SET adjusted_due = ? WHERE id = ? AND sent_at IS NOT NULL",
                (due.isoformat(), request_id),
            )
            if cursor.rowcount != 1:
                raise StorageError("Select a sent request before adjusting its deadline")
            self._record_event(request_id, "deadline_adjusted", now)
            return self.get_request(request_id)

    def record_reply(self, request_id: str, item_id: str, now: datetime, *, ambiguous: bool = False) -> bool:
        kind = "possible_reply" if ambiguous else "reply"
        with self._transaction():
            cursor = self._db.execute(
                """INSERT INTO request_events (request_id, kind, timestamp, item_id) VALUES (?, ?, ?, ?)
                   ON CONFLICT (request_id, kind, item_id) DO NOTHING""",
                (request_id, kind, now.astimezone(UTC).isoformat(), item_id),
            )
            if not ambiguous and cursor.rowcount:
                self._db.execute(
                    "UPDATE requests SET state = 'reply' WHERE id = ? AND state = 'sent'", (request_id,)
                )
            return cursor.rowcount > 0 and not ambiguous

    def reconcile_sent(self, request_id: str, sent: datetime, message_id: str, thread_id: str | None) -> None:
        with self._transaction():
            cursor = self._db.execute(
                """UPDATE requests SET state = 'sent', sent_at = ?, message_id = ?, thread_id = coalesce(?, thread_id)
                   WHERE id = ? AND state IN ('pending', 'uncertain')""",
                (sent.astimezone(UTC).isoformat(), message_id, thread_id, request_id),
            )
            if cursor.rowcount:
                self._record_event(request_id, "sent", sent)
            else:
                self._db.execute(
                    """UPDATE requests SET message_id = coalesce(?, message_id), thread_id = coalesce(?, thread_id)
                       WHERE id = ? AND state IN ('sent', 'reply', 'fulfilled')""",
                    (message_id, thread_id, request_id),
                )

    def remember_notification(self, request_id: str, day: str, now: datetime) -> bool:
        with self._transaction():
            cursor = self._db.execute(
                """INSERT INTO request_events (request_id, kind, timestamp, item_id)
                   VALUES (?, 'reminder', ?, ?) ON CONFLICT (request_id, kind, item_id) DO NOTHING""",
                (request_id, now.astimezone(UTC).isoformat(), day),
            )
            return cursor.rowcount == 1

    def preference(self, name: str, default: str = "") -> str:
        with self._lock:
            row = self._db.execute("SELECT value FROM preferences WHERE name = ?", (name,)).fetchone()
            return row[0] if row else default

    def set_preference(self, name: str, value: str) -> None:
        with self._transaction():
            self._db.execute(
                """INSERT INTO preferences VALUES (?, ?)
                   ON CONFLICT (name) DO UPDATE SET value = excluded.value""",
                (name, value),
            )
