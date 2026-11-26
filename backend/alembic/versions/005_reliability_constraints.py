"""Add flow uniqueness, active alert uniqueness, and worker lease fields

Revision ID: 005_reliability_constraints
Revises: 004_detection_jobs
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "005_reliability_constraints"
down_revision: Union[str, None] = "004_detection_jobs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    duplicate_predictions = op.get_bind().execute(sa.text(
        "SELECT COUNT(*) FROM (SELECT flow_id FROM predictions GROUP BY flow_id HAVING COUNT(*) > 1) duplicates"
    )).scalar_one()
    if duplicate_predictions:
        raise RuntimeError(
            f"Refusing migration: {duplicate_predictions} flows have duplicate prediction rows. "
            "Reconcile predictions before adding the unique constraint."
        )
    op.create_unique_constraint("uq_predictions_flow", "predictions", ["flow_id"])

    duplicate_flows = op.get_bind().execute(sa.text(
        """
        SELECT COUNT(*) FROM (
            SELECT session_id, flow_key, window_start
            FROM flow_records
            GROUP BY session_id, flow_key, window_start
            HAVING COUNT(*) > 1
        ) duplicates
        """
    )).scalar_one()
    if duplicate_flows:
        raise RuntimeError(
            f"Refusing migration: {duplicate_flows} duplicate logical flow groups exist. "
            "Reconcile duplicates before adding the unique constraint."
        )

    op.create_unique_constraint(
        "uq_flow_records_session_flow_window",
        "flow_records",
        ["session_id", "flow_key", "window_start"],
    )

    # Alert identity is scoped to a capture session. Preserve every original
    # alert involved in a same-session merge before consolidating active duplicates.
    op.execute(sa.text("""
        CREATE TEMPORARY TABLE _alert_dedup_groups
        ON COMMIT DROP
        AS
        SELECT
            session_id,
            fingerprint,
            SUM(occurrence_count)::integer AS merged_occurrence_count,
            MIN(first_seen) AS merged_first_seen,
            MAX(last_seen) AS merged_last_seen,
            CASE
                WHEN BOOL_OR(status = 'ACKNOWLEDGED') THEN 'ACKNOWLEDGED'
                ELSE 'OPEN'
            END AS merged_status,
            (ARRAY_AGG(
                id ORDER BY
                    CASE severity
                        WHEN 'CRITICAL' THEN 4
                        WHEN 'HIGH' THEN 3
                        WHEN 'MEDIUM' THEN 2
                        WHEN 'LOW' THEN 1
                        ELSE 0
                    END DESC,
                    last_seen DESC,
                    created_at DESC,
                    id DESC
            ))[1] AS keeper_id,
            (ARRAY_AGG(
                severity ORDER BY
                    CASE severity
                        WHEN 'CRITICAL' THEN 4
                        WHEN 'HIGH' THEN 3
                        WHEN 'MEDIUM' THEN 2
                        WHEN 'LOW' THEN 1
                        ELSE 0
                    END DESC,
                    last_seen DESC,
                    created_at DESC,
                    id DESC
            ))[1] AS merged_severity
        FROM alerts
        WHERE status IN ('OPEN', 'ACKNOWLEDGED')
        GROUP BY session_id, fingerprint
        HAVING COUNT(*) > 1
    """))

    # Keep the original rows outside the active table for auditability.
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS alert_dedup_archive AS
        SELECT
            alerts.*,
            CURRENT_TIMESTAMP AS archived_at,
            CAST('Merged same-session active alert duplicates during migration 005'
                 AS VARCHAR(160)) AS archive_reason
        FROM alerts
        WHERE FALSE
    """))
    op.execute(sa.text("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_alert_dedup_archive_id
        ON alert_dedup_archive (id)
    """))
    op.execute(sa.text("""
        INSERT INTO alert_dedup_archive
        SELECT
            a.*,
            CURRENT_TIMESTAMP,
            CAST('Merged same-session active alert duplicates during migration 005'
                 AS VARCHAR(160))
        FROM alerts AS a
        JOIN _alert_dedup_groups AS g
          ON a.fingerprint = g.fingerprint
         AND a.session_id IS NOT DISTINCT FROM g.session_id
        WHERE a.status IN ('OPEN', 'ACKNOWLEDGED')
        ON CONFLICT (id) DO NOTHING
    """))

    # Keep the most severe/latest alert as the canonical row. Preserve the
    # combined occurrence history, full time range, and acknowledgement state.
    op.execute(sa.text("""
        UPDATE alerts AS a
        SET
            severity = g.merged_severity,
            occurrence_count = g.merged_occurrence_count,
            first_seen = g.merged_first_seen,
            last_seen = g.merged_last_seen,
            status = g.merged_status
        FROM _alert_dedup_groups AS g
        WHERE a.id = g.keeper_id
    """))
    op.execute(sa.text("""
        DELETE FROM alerts AS a
        USING _alert_dedup_groups AS g
        WHERE a.fingerprint = g.fingerprint
          AND a.session_id IS NOT DISTINCT FROM g.session_id
          AND a.status IN ('OPEN', 'ACKNOWLEDGED')
          AND a.id <> g.keeper_id
    """))

    remaining_duplicate_alerts = op.get_bind().execute(sa.text("""
        SELECT COUNT(*) FROM (
            SELECT session_id, fingerprint
            FROM alerts
            WHERE status IN ('OPEN', 'ACKNOWLEDGED')
            GROUP BY session_id, fingerprint
            HAVING COUNT(*) > 1
        ) duplicates
    """)).scalar_one()
    if remaining_duplicate_alerts:
        raise RuntimeError(
            f"Refusing migration: {remaining_duplicate_alerts} duplicate active "
            "session/fingerprint groups remain after reconciliation."
        )

    # Non-NULL sessions are unique by (session_id, fingerprint). NULL-session
    # alerts have a separate global-scope unique index.
    op.create_index(
        "uq_alerts_active_session_fingerprint",
        "alerts",
        ["session_id", "fingerprint"],
        unique=True,
        postgresql_where=sa.text(
            "status IN ('OPEN', 'ACKNOWLEDGED') AND session_id IS NOT NULL"
        ),
        sqlite_where=sa.text(
            "status IN ('OPEN', 'ACKNOWLEDGED') AND session_id IS NOT NULL"
        ),
    )
    op.create_index(
        "uq_alerts_active_null_session_fingerprint",
        "alerts",
        ["fingerprint"],
        unique=True,
        postgresql_where=sa.text(
            "status IN ('OPEN', 'ACKNOWLEDGED') AND session_id IS NULL"
        ),
        sqlite_where=sa.text(
            "status IN ('OPEN', 'ACKNOWLEDGED') AND session_id IS NULL"
        ),
    )

    op.add_column("detection_jobs", sa.Column("worker_id", sa.String(length=128), nullable=True))
    op.add_column("detection_jobs", sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("detection_jobs", sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_detection_jobs_worker_id", "detection_jobs", ["worker_id"])


def downgrade() -> None:
    op.drop_constraint("uq_predictions_flow", "predictions", type_="unique")
    op.drop_index("ix_detection_jobs_worker_id", table_name="detection_jobs")
    op.drop_column("detection_jobs", "lease_expires_at")
    op.drop_column("detection_jobs", "heartbeat_at")
    op.drop_column("detection_jobs", "worker_id")
    op.drop_index("uq_alerts_active_null_session_fingerprint", table_name="alerts")
    op.drop_index("uq_alerts_active_session_fingerprint", table_name="alerts")
    # alert_dedup_archive is intentionally retained as an audit record.
    op.drop_constraint(
        "uq_flow_records_session_flow_window",
        "flow_records",
        type_="unique",
    )
