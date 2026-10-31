"""Create flow_records table

Revision ID: 002_flow_records
Revises: 001_initial_capture_sessions
Create Date: 2026-10-12 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

# revision identifiers, used by Alembic.
revision: str = "002_flow_records"
down_revision: Union[str, None] = "001_initial_capture_sessions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "flow_records",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "session_id",
            UUID(as_uuid=True),
            sa.ForeignKey("capture_sessions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("flow_key", sa.String(255), nullable=False),
        sa.Column("src_ip", sa.String(64), nullable=True),
        sa.Column("dst_ip", sa.String(64), nullable=True),
        sa.Column("src_port", sa.Integer(), nullable=True),
        sa.Column("dst_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(32), nullable=False),
        sa.Column("protocol_num", sa.Integer(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("duration_seconds", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("packet_count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("byte_count", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("fwd_packets", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("rev_packets", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("fwd_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("rev_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("packets_per_second", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("bytes_per_second", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("min_packet_size", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_packet_size", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("avg_packet_size", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("tcp_syn_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tcp_ack_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tcp_fin_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tcp_rst_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tcp_psh_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("dns_query_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("dns_unique_query_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("upload_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("download_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("upload_ratio", sa.Float(), nullable=True),
        sa.Column("is_local", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("is_broadcast", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("is_multicast", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column(
            "features",
            JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("feature_schema_version", sa.String(32), nullable=False, server_default="1.0"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    op.create_index(
        op.f("ix_flow_records_session_id"),
        "flow_records",
        ["session_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_flow_records_window_start"),
        "flow_records",
        ["window_start"],
        unique=False,
    )
    op.create_index(
        op.f("ix_flow_records_flow_key"),
        "flow_records",
        ["flow_key"],
        unique=False,
    )
    op.create_index(
        op.f("ix_flow_records_src_ip"),
        "flow_records",
        ["src_ip"],
        unique=False,
    )
    op.create_index(
        op.f("ix_flow_records_dst_ip"),
        "flow_records",
        ["dst_ip"],
        unique=False,
    )
    op.create_index(
        op.f("ix_flow_records_protocol"),
        "flow_records",
        ["protocol"],
        unique=False,
    )
    op.create_index(
        "ix_flow_records_session_window",
        "flow_records",
        ["session_id", "window_start"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_flow_records_session_window", table_name="flow_records")
    op.drop_index(op.f("ix_flow_records_protocol"), table_name="flow_records")
    op.drop_index(op.f("ix_flow_records_dst_ip"), table_name="flow_records")
    op.drop_index(op.f("ix_flow_records_src_ip"), table_name="flow_records")
    op.drop_index(op.f("ix_flow_records_flow_key"), table_name="flow_records")
    op.drop_index(op.f("ix_flow_records_window_start"), table_name="flow_records")
    op.drop_index(op.f("ix_flow_records_session_id"), table_name="flow_records")
    op.drop_table("flow_records")
