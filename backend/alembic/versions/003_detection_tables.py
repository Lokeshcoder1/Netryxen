"""Add model_registry, predictions, and alerts tables

Revision ID: 003_detection_tables
Revises: 002_flow_records
Create Date: 2026-11-07 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

# revision identifiers, used by Alembic.
revision: str = "003_detection_tables"
down_revision: Union[str, None] = "002_flow_records"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ---- model_registry ----
    op.create_table(
        "model_registry",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column("algorithm", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="TRAINING"),
        sa.Column("feature_names", JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("feature_schema_version", sa.String(32), nullable=False, server_default="1.0"),
        sa.Column(
            "training_session_id",
            UUID(as_uuid=True),
            sa.ForeignKey("capture_sessions.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("training_sample_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("training_params", JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("artifact_path", sa.String(512), nullable=True),
        sa.Column("artifact_checksum", sa.String(128), nullable=True),
        sa.Column("evaluation_info", JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index(op.f("ix_model_registry_name"), "model_registry", ["name"])
    op.create_index(op.f("ix_model_registry_status"), "model_registry", ["status"])

    # ---- predictions ----
    op.create_table(
        "predictions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "flow_id",
            UUID(as_uuid=True),
            sa.ForeignKey("flow_records.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "model_id",
            UUID(as_uuid=True),
            sa.ForeignKey("model_registry.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("model_version", sa.String(64), nullable=True),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("raw_score", sa.Float(), nullable=True),
        sa.Column("raw_prediction", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index(op.f("ix_predictions_flow_id"), "predictions", ["flow_id"])
    op.create_index(op.f("ix_predictions_model_id"), "predictions", ["model_id"])
    op.create_index(op.f("ix_predictions_status"), "predictions", ["status"])
    op.create_index("ix_predictions_flow_model", "predictions", ["flow_id", "model_id"])

    # ---- alerts ----
    op.create_table(
        "alerts",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "flow_id",
            UUID(as_uuid=True),
            sa.ForeignKey("flow_records.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "session_id",
            UUID(as_uuid=True),
            sa.ForeignKey("capture_sessions.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("detection_source", sa.String(32), nullable=False),
        sa.Column("model_version", sa.String(64), nullable=True),
        sa.Column("rule_id", sa.String(128), nullable=True),
        sa.Column("rule_evidence", JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.String(255), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="OPEN"),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index(op.f("ix_alerts_flow_id"), "alerts", ["flow_id"])
    op.create_index(op.f("ix_alerts_session_id"), "alerts", ["session_id"])
    op.create_index(op.f("ix_alerts_rule_id"), "alerts", ["rule_id"])
    op.create_index(op.f("ix_alerts_severity"), "alerts", ["severity"])
    op.create_index(op.f("ix_alerts_status"), "alerts", ["status"])
    op.create_index(op.f("ix_alerts_fingerprint"), "alerts", ["fingerprint"])
    op.create_index("ix_alerts_fingerprint_status", "alerts", ["fingerprint", "status"])


def downgrade() -> None:
    op.drop_index("ix_alerts_fingerprint_status", table_name="alerts")
    op.drop_index(op.f("ix_alerts_fingerprint"), table_name="alerts")
    op.drop_index(op.f("ix_alerts_status"), table_name="alerts")
    op.drop_index(op.f("ix_alerts_severity"), table_name="alerts")
    op.drop_index(op.f("ix_alerts_rule_id"), table_name="alerts")
    op.drop_index(op.f("ix_alerts_session_id"), table_name="alerts")
    op.drop_index(op.f("ix_alerts_flow_id"), table_name="alerts")
    op.drop_table("alerts")

    op.drop_index("ix_predictions_flow_model", table_name="predictions")
    op.drop_index(op.f("ix_predictions_status"), table_name="predictions")
    op.drop_index(op.f("ix_predictions_model_id"), table_name="predictions")
    op.drop_index(op.f("ix_predictions_flow_id"), table_name="predictions")
    op.drop_table("predictions")

    op.drop_index(op.f("ix_model_registry_status"), table_name="model_registry")
    op.drop_index(op.f("ix_model_registry_name"), table_name="model_registry")
    op.drop_table("model_registry")
