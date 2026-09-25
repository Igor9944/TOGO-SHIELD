"""create scans table

Revision ID: 0001
"""
from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("level", sa.String(length=16), nullable=False),
        sa.Column("threat_type", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("telegram_chat_id", sa.Integer(), nullable=True),
        sa.Column("telegram_user_id", sa.Integer(), nullable=True),
        sa.Column("telegram_message_id", sa.Integer(), nullable=True),
        sa.Column("media_type", sa.String(length=32), nullable=True),
        sa.Column("indicators_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("threat_intelligence_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("score_breakdown_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_scans_source", "scans", ["source"])
    op.create_index("ix_scans_score", "scans", ["score"])
    op.create_index("ix_scans_level", "scans", ["level"])
    op.create_index("ix_scans_telegram_chat_id", "scans", ["telegram_chat_id"])
    op.create_index("ix_scans_telegram_user_id", "scans", ["telegram_user_id"])
    op.create_index("uq_scans_telegram_message_id", "scans", ["telegram_message_id"], unique=True)


def downgrade() -> None:
    op.drop_table("scans")