"""widen Telegram identifiers to BIGINT

Revision ID: 0002
Revises: 0001
"""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("scans", "telegram_chat_id", existing_type=sa.Integer(), type_=sa.BigInteger(), existing_nullable=True)
    op.alter_column("scans", "telegram_user_id", existing_type=sa.Integer(), type_=sa.BigInteger(), existing_nullable=True)
    op.alter_column("scans", "telegram_message_id", existing_type=sa.Integer(), type_=sa.BigInteger(), existing_nullable=True)


def downgrade() -> None:
    op.alter_column("scans", "telegram_chat_id", existing_type=sa.BigInteger(), type_=sa.Integer(), existing_nullable=True)
    op.alter_column("scans", "telegram_user_id", existing_type=sa.BigInteger(), type_=sa.Integer(), existing_nullable=True)
    op.alter_column("scans", "telegram_message_id", existing_type=sa.BigInteger(), type_=sa.Integer(), existing_nullable=True)