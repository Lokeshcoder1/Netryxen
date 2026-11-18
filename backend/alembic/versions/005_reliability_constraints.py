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

    duplicate_alerts = op.get_bind().execute(sa.text(
        """
        SELECT COUNT(*) FROM (
            SELECT fingerprint
            FROM alerts
            WHERE status IN ('OPEN', 'ACKNOWLEDGED')
            GROUP BY fingerprint
            HAVING COUNT(*) > 1
        ) duplicates
        """
    )).scalar_one()
    if duplicate_alerts:
        raise RuntimeError(
            f"Refusing migration: {duplicate_alerts} active alert fingerprints are duplicated. "
            "Merge them and preserve the highest severity before adding the partial unique index."
        )

    op.create_index(
        "uq_alerts_active_fingerprint",
        "alerts",
        ["fingerprint"],
        unique=True,
        postgresql_where=sa.text("status IN ('OPEN', 'ACKNOWLEDGED')"),
        sqlite_where=sa.text("status IN ('OPEN', 'ACKNOWLEDGED')"),
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
    op.drop_index("uq_alerts_active_fingerprint", table_name="alerts")
    op.drop_constraint(
        "uq_flow_records_session_flow_window",
        "flow_records",
        type_="unique",
    )
