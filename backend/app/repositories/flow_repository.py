from typing import Any, Dict, List, Optional, Tuple
import uuid

from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session

from app.models.capture_session import CaptureSession
from app.models.flow_record import FlowRecord
from app.schemas.flow import FlowFilterParams


class FlowRepository:
    """
    Data access layer for flow_records table and dashboard summary aggregations.
    """

    @staticmethod
    def create_batch(db: Session, records: List[FlowRecord]) -> int:
        """
        Inserts a batch of flow records efficiently.
        """
        if not records:
            return 0
        db.add_all(records)
        db.commit()
        return len(records)

    @staticmethod
    def get_by_id(db: Session, flow_id: uuid.UUID) -> Optional[FlowRecord]:
        """
        Fetches a single flow record by its UUID.
        """
        stmt = select(FlowRecord).where(FlowRecord.id == flow_id)
        return db.execute(stmt).scalar_one_or_none()

    @staticmethod
    def list_flows(
        db: Session,
        filters: FlowFilterParams,
    ) -> Tuple[List[FlowRecord], int]:
        """
        Retrieves a filtered, paginated list of flow records and total matching count.
        """
        query = select(FlowRecord)

        if filters.session_id:
            query = query.where(FlowRecord.session_id == filters.session_id)
        if filters.protocol:
            query = query.where(func.upper(FlowRecord.protocol) == filters.protocol.upper())
        if filters.src_ip:
            query = query.where(FlowRecord.src_ip == filters.src_ip)
        if filters.dst_ip:
            query = query.where(FlowRecord.dst_ip == filters.dst_ip)
        if filters.ip:
            query = query.where(
                or_(
                    FlowRecord.src_ip == filters.ip,
                    FlowRecord.dst_ip == filters.ip,
                )
            )
        if filters.start_time:
            query = query.where(FlowRecord.window_start >= filters.start_time)
        if filters.end_time:
            query = query.where(FlowRecord.window_end <= filters.end_time)
        if filters.min_packet_count is not None:
            query = query.where(FlowRecord.packet_count >= filters.min_packet_count)

        # Count total
        count_query = select(func.count()).select_from(query.subquery())
        total = db.execute(count_query).scalar_one()

        # Apply ordering and pagination
        paginated_query = (
            query.order_by(desc(FlowRecord.window_start))
            .offset(filters.skip)
            .limit(filters.limit)
        )
        items = list(db.execute(paginated_query).scalars().all())

        return items, total

    @staticmethod
    def get_dashboard_stats(db: Session) -> Dict[str, Any]:
        """
        Computes aggregate metrics for dashboard summary:
        session counts, flow counts, total bytes/packets, protocol breakdown, and top talkers.
        """
        # Total sessions
        total_sessions = db.execute(select(func.count(CaptureSession.id))).scalar_one() or 0

        # Flow aggregates
        flow_agg = db.execute(
            select(
                func.count(FlowRecord.id).label("flow_count"),
                func.coalesce(func.sum(FlowRecord.packet_count), 0).label("pkt_sum"),
                func.coalesce(func.sum(FlowRecord.byte_count), 0).label("byte_sum"),
            )
        ).one()

        total_flows = flow_agg.flow_count
        total_packets = flow_agg.pkt_sum
        total_bytes = flow_agg.byte_sum

        # Protocol distribution
        proto_rows = db.execute(
            select(
                FlowRecord.protocol,
                func.count(FlowRecord.id).label("cnt"),
            )
            .group_by(FlowRecord.protocol)
            .order_by(desc("cnt"))
        ).all()
        protocol_distribution = {row[0]: row[1] for row in proto_rows}

        # Top talker source IPs by bytes
        top_talker_rows = db.execute(
            select(
                FlowRecord.src_ip,
                func.coalesce(func.sum(FlowRecord.packet_count), 0).label("pkts"),
                func.coalesce(func.sum(FlowRecord.byte_count), 0).label("bytes"),
            )
            .where(FlowRecord.src_ip.isnot(None))
            .group_by(FlowRecord.src_ip)
            .order_by(desc("bytes"))
            .limit(10)
        ).all()

        top_talkers = [
            {"ip": r[0], "packets": int(r[1]), "bytes": int(r[2])}
            for r in top_talker_rows
        ]

        # Recent 10 flow records
        recent_flows = list(
            db.execute(
                select(FlowRecord)
                .order_by(desc(FlowRecord.created_at))
                .limit(10)
            )
            .scalars()
            .all()
        )

        return {
            "total_sessions": total_sessions,
            "total_flows": total_flows,
            "total_packets": int(total_packets),
            "total_bytes": int(total_bytes),
            "protocol_distribution": protocol_distribution,
            "top_talkers": top_talkers,
            "recent_flows": recent_flows,
        }
