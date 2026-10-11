"""Initial capture_sessions table

Revision ID: 001_initial_capture_sessions
Revises: 
Create Date: 2026-10-11 14:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

# revision identifiers, used by Alembic.
revision: str = "001_initial_capture_sessions"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "capture_sessions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("interface_id", sa.String(255), nullable=False),
        sa.Column("session_mode", sa.String(32), nullable=False, server_default="MONITORING"),
        sa.Column("status", sa.String(32), nullable=False, server_default="RUNNING"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("stopped_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("packets_seen", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("packets_enqueued", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("packets_dropped", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("error_summary", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "session_mode IN ('BASELINE', 'MONITORING')",
            name="chk_capture_session_mode",
        ),
        sa.CheckConstraint(
            "status IN ('RUNNING', 'STOPPED', 'FAILED')",
            name="chk_capture_session_status",
        ),
    )
    op.create_index(
        op.f("ix_capture_sessions_interface_id"),
        "capture_sessions",
        ["interface_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_capture_sessions_status"),
        "capture_sessions",
        ["status"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_capture_sessions_status"), table_name="capture_sessions")
    op.drop_index(op.f("ix_capture_sessions_interface_id"), table_name="capture_sessions")
    op.drop_table("capture_sessions")
