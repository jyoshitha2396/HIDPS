import json
from collections import defaultdict
from typing import Any, Dict, Iterable, Optional, Sequence


class DatabaseStore:
    def __init__(self, database_url: str):
        self.database_url = database_url.strip()
        self.enabled = bool(self.database_url)
        self.initialized = False

    def _connect(self):
        import psycopg
        from psycopg.rows import dict_row

        return psycopg.connect(self.database_url, autocommit=True, row_factory=dict_row)

    def _json_dumps(self, value: Any) -> str:
        return json.dumps(value)

    def _json_loads(self, value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, str):
            return json.loads(value)
        return value

    def initialize(
        self,
        default_users: Iterable[Dict[str, Any]],
        default_credentials: Dict[str, Dict[str, Any]],
    ) -> None:
        if not self.enabled or self.initialized:
            return

        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS soc_users (
                    user_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE,
                    role TEXT NOT NULL,
                    team TEXT NOT NULL,
                    shift TEXT NOT NULL,
                    status TEXT NOT NULL,
                    queue_level TEXT NOT NULL,
                    permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
                    password_hash TEXT NOT NULL,
                    failed_attempts INTEGER NOT NULL DEFAULT 0,
                    locked_until DOUBLE PRECISION NOT NULL DEFAULT 0,
                    password_updated_at DOUBLE PRECISION NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS soc_sessions (
                    token TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES soc_users(user_id) ON DELETE CASCADE,
                    client_ip TEXT NOT NULL,
                    created_at DOUBLE PRECISION NOT NULL,
                    last_seen DOUBLE PRECISION NOT NULL,
                    expires_at DOUBLE PRECISION NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS soc_alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp DOUBLE PRECISION NOT NULL,
                    status TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    queue_level TEXT NOT NULL,
                    assigned_analyst TEXT NULL,
                    disposition TEXT NOT NULL,
                    attack_type TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    telemetry_source TEXT NOT NULL,
                    asset_name TEXT NOT NULL,
                    payload JSONB NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS soc_reports (
                    alert_id TEXT PRIMARY KEY REFERENCES soc_alerts(alert_id) ON DELETE CASCADE,
                    summary TEXT NOT NULL,
                    author TEXT NOT NULL,
                    disposition TEXT NOT NULL,
                    updated_at DOUBLE PRECISION NOT NULL,
                    payload JSONB NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS soc_feedback (
                    feedback_id BIGSERIAL PRIMARY KEY,
                    alert_id TEXT NOT NULL REFERENCES soc_alerts(alert_id) ON DELETE CASCADE,
                    timestamp DOUBLE PRECISION NOT NULL,
                    verdict TEXT NOT NULL,
                    analyst TEXT NOT NULL,
                    payload JSONB NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS soc_escalations (
                    escalation_id BIGSERIAL PRIMARY KEY,
                    alert_id TEXT NOT NULL REFERENCES soc_alerts(alert_id) ON DELETE CASCADE,
                    timestamp DOUBLE PRECISION NOT NULL,
                    payload JSONB NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS soc_actions (
                    action_id TEXT PRIMARY KEY,
                    alert_id TEXT NULL REFERENCES soc_alerts(alert_id) ON DELETE SET NULL,
                    created_at DOUBLE PRECISION NOT NULL,
                    status TEXT NOT NULL,
                    executed_at DOUBLE PRECISION NULL,
                    payload JSONB NOT NULL,
                    created_at_db TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_soc_alerts_timestamp ON soc_alerts (timestamp DESC)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_soc_alerts_status ON soc_alerts (status, severity)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_soc_feedback_alert_time ON soc_feedback (alert_id, timestamp DESC)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_soc_escalations_alert_time ON soc_escalations (alert_id, timestamp DESC)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_soc_actions_status_time ON soc_actions (status, created_at DESC)"
            )

            existing_row = conn.execute("SELECT COUNT(*) AS count FROM soc_users").fetchone()
            if existing_row and int(existing_row["count"]) == 0:
                for user in default_users:
                    credential = default_credentials.get(str(user["user_id"]))
                    if not credential:
                        continue
                    conn.execute(
                        """
                        INSERT INTO soc_users (
                            user_id,
                            name,
                            email,
                            role,
                            team,
                            shift,
                            status,
                            queue_level,
                            permissions,
                            password_hash,
                            failed_attempts,
                            locked_until,
                            password_updated_at
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s)
                        """,
                        (
                            user["user_id"],
                            user["name"],
                            user["email"],
                            user["role"],
                            user["team"],
                            user["shift"],
                            user["status"],
                            user["queue_level"],
                            self._json_dumps(user["permissions"]),
                            credential["password_hash"],
                            0,
                            0.0,
                            credential["password_updated_at"],
                        ),
                    )

        self.initialized = True

    def _normalize_permissions(self, raw_permissions: Any):
        if isinstance(raw_permissions, str):
            return json.loads(raw_permissions)
        return list(raw_permissions or [])

    def _user_from_row(self, row: Dict[str, Any]) -> Dict[str, Any]:
        user = dict(row)
        user["permissions"] = self._normalize_permissions(user.get("permissions"))
        return user

    def list_users(self) -> list[Dict[str, Any]]:
        if not self.enabled:
            return []
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT user_id, name, email, role, team, shift, status, queue_level, permissions
                FROM soc_users
                ORDER BY created_at ASC, name ASC
                """
            ).fetchall()
        return [self._user_from_row(row) for row in rows]

    def find_user_by_identifier(self, identifier: str) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None
        normalized = identifier.strip().lower()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT user_id, name, email, role, team, shift, status, queue_level, permissions,
                       password_hash, failed_attempts, locked_until, password_updated_at
                FROM soc_users
                WHERE lower(user_id) = %s OR lower(name) = %s OR lower(email) = %s
                LIMIT 1
                """,
                (normalized, normalized, normalized),
            ).fetchone()
        return self._user_from_row(row) if row else None

    def update_login_failure(self, user_id: str, failed_attempts: int, locked_until: float) -> None:
        if not self.enabled:
            return
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE soc_users
                SET failed_attempts = %s, locked_until = %s
                WHERE user_id = %s
                """,
                (failed_attempts, locked_until, user_id),
            )

    def reset_login_failures(self, user_id: str) -> None:
        self.update_login_failure(user_id, 0, 0.0)

    def create_session(self, token: str, user_id: str, client_ip: str, created_at: float, expires_at: float) -> None:
        if not self.enabled:
            return
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO soc_sessions (token, user_id, client_ip, created_at, last_seen, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (token, user_id, client_ip, created_at, created_at, expires_at),
            )

    def get_session_user(self, token: str) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT s.token, s.user_id AS session_user_id, s.client_ip, s.created_at, s.last_seen, s.expires_at,
                       u.user_id, u.name, u.email, u.role, u.team, u.shift, u.status, u.queue_level, u.permissions
                FROM soc_sessions s
                JOIN soc_users u ON u.user_id = s.user_id
                WHERE s.token = %s
                LIMIT 1
                """,
                (token,),
            ).fetchone()
        return self._user_from_row(row) if row else None

    def touch_session(self, token: str, last_seen: float, expires_at: float) -> None:
        if not self.enabled:
            return
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE soc_sessions
                SET last_seen = %s, expires_at = %s
                WHERE token = %s
                """,
                (last_seen, expires_at, token),
            )

    def revoke_session(self, token: str) -> None:
        if not self.enabled:
            return
        with self._connect() as conn:
            conn.execute("DELETE FROM soc_sessions WHERE token = %s", (token,))

    def revoke_expired_sessions(self, now: float) -> None:
        if not self.enabled:
            return
        with self._connect() as conn:
            conn.execute("DELETE FROM soc_sessions WHERE expires_at <= %s", (now,))

    def insert_user(self, user: Dict[str, Any], password_hash: str, password_updated_at: float) -> None:
        if not self.enabled:
            return
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO soc_users (
                    user_id,
                    name,
                    email,
                    role,
                    team,
                    shift,
                    status,
                    queue_level,
                    permissions,
                    password_hash,
                    failed_attempts,
                    locked_until,
                    password_updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s)
                """,
                (
                    user["user_id"],
                    user["name"],
                    user["email"],
                    user["role"],
                    user["team"],
                    user["shift"],
                    user["status"],
                    user["queue_level"],
                    self._json_dumps(user["permissions"]),
                    password_hash,
                    0,
                    0.0,
                    password_updated_at,
                ),
            )

    def upsert_alert(self, alert: Dict[str, Any]) -> None:
        if not self.enabled:
            return
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO soc_alerts (
                    alert_id,
                    timestamp,
                    status,
                    severity,
                    queue_level,
                    assigned_analyst,
                    disposition,
                    attack_type,
                    source_ip,
                    telemetry_source,
                    asset_name,
                    payload,
                    updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, NOW())
                ON CONFLICT (alert_id) DO UPDATE
                SET
                    timestamp = EXCLUDED.timestamp,
                    status = EXCLUDED.status,
                    severity = EXCLUDED.severity,
                    queue_level = EXCLUDED.queue_level,
                    assigned_analyst = EXCLUDED.assigned_analyst,
                    disposition = EXCLUDED.disposition,
                    attack_type = EXCLUDED.attack_type,
                    source_ip = EXCLUDED.source_ip,
                    telemetry_source = EXCLUDED.telemetry_source,
                    asset_name = EXCLUDED.asset_name,
                    payload = EXCLUDED.payload,
                    updated_at = NOW()
                """,
                (
                    alert["id"],
                    alert["timestamp"],
                    alert["status"],
                    alert["severity"],
                    alert["queue_level"],
                    alert.get("assigned_analyst"),
                    alert["disposition"],
                    alert["attack_type"],
                    alert["source_ip"],
                    alert["telemetry_source"],
                    alert["asset_name"],
                    self._json_dumps(alert),
                ),
            )

    def list_alerts(self, limit: int = 5000) -> list[Dict[str, Any]]:
        if not self.enabled:
            return []
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT payload
                FROM (
                    SELECT payload, timestamp
                    FROM soc_alerts
                    ORDER BY timestamp DESC
                    LIMIT %s
                ) recent
                ORDER BY timestamp ASC
                """,
                (limit,),
            ).fetchall()
        return [self._json_loads(row["payload"]) for row in rows]

    def get_alert_count(self) -> int:
        if not self.enabled:
            return 0
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM soc_alerts").fetchone()
        return int(row["count"]) if row else 0

    def upsert_report(self, alert_id: str, report: Dict[str, Any]) -> None:
        if not self.enabled:
            return
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO soc_reports (alert_id, summary, author, disposition, updated_at, payload)
                VALUES (%s, %s, %s, %s, %s, %s::jsonb)
                ON CONFLICT (alert_id) DO UPDATE
                SET
                    summary = EXCLUDED.summary,
                    author = EXCLUDED.author,
                    disposition = EXCLUDED.disposition,
                    updated_at = EXCLUDED.updated_at,
                    payload = EXCLUDED.payload
                """,
                (
                    alert_id,
                    report["summary"],
                    report["author"],
                    report["disposition"],
                    report["updated_at"],
                    self._json_dumps(report),
                ),
            )

    def list_reports(self) -> dict[str, Dict[str, Any]]:
        if not self.enabled:
            return {}
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT alert_id, payload
                FROM soc_reports
                ORDER BY updated_at DESC
                """
            ).fetchall()
        return {str(row["alert_id"]): self._json_loads(row["payload"]) for row in rows}

    def insert_feedback(self, alert_id: str, feedback: Dict[str, Any]) -> None:
        if not self.enabled:
            return
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO soc_feedback (alert_id, timestamp, verdict, analyst, payload)
                VALUES (%s, %s, %s, %s, %s::jsonb)
                """,
                (
                    alert_id,
                    feedback["timestamp"],
                    feedback["verdict"],
                    feedback["analyst"],
                    self._json_dumps(feedback),
                ),
            )

    def list_feedback(self, limit: int = 200) -> list[Dict[str, Any]]:
        if not self.enabled:
            return []
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT payload
                FROM soc_feedback
                ORDER BY timestamp DESC
                LIMIT %s
                """,
                (limit,),
            ).fetchall()
        return [self._json_loads(row["payload"]) for row in rows]

    def insert_escalation(self, alert_id: str, escalation: Dict[str, Any]) -> None:
        if not self.enabled:
            return
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO soc_escalations (alert_id, timestamp, payload)
                VALUES (%s, %s, %s::jsonb)
                """,
                (alert_id, escalation["timestamp"], self._json_dumps(escalation)),
            )

    def list_escalations(self) -> dict[str, list[Dict[str, Any]]]:
        if not self.enabled:
            return {}
        grouped: dict[str, list[Dict[str, Any]]] = defaultdict(list)
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT alert_id, payload
                FROM soc_escalations
                ORDER BY timestamp ASC
                """
            ).fetchall()
        for row in rows:
            grouped[str(row["alert_id"])].append(self._json_loads(row["payload"]))
        return dict(grouped)

    def upsert_action(self, action: Dict[str, Any]) -> None:
        if not self.enabled:
            return
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO soc_actions (action_id, alert_id, created_at, status, executed_at, payload)
                VALUES (%s, %s, %s, %s, %s, %s::jsonb)
                ON CONFLICT (action_id) DO UPDATE
                SET
                    alert_id = EXCLUDED.alert_id,
                    created_at = EXCLUDED.created_at,
                    status = EXCLUDED.status,
                    executed_at = EXCLUDED.executed_at,
                    payload = EXCLUDED.payload
                """,
                (
                    action["action_id"],
                    action.get("alert_id"),
                    action["created_at"],
                    action["status"],
                    action.get("executed_at"),
                    self._json_dumps(action),
                ),
            )

    def list_actions(
        self,
        statuses: Optional[Sequence[str]] = None,
        limit: int = 500,
    ) -> list[Dict[str, Any]]:
        if not self.enabled:
            return []
        query = """
            SELECT payload
            FROM soc_actions
        """
        params: list[Any] = []
        if statuses:
            query += " WHERE status = ANY(%s)"
            params.append(list(statuses))
        query += " ORDER BY created_at DESC LIMIT %s"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._json_loads(row["payload"]) for row in rows]
