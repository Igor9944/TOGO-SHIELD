"""Change Telegram identifiers from INTEGER to BIGINT.

Revision ID: 20260925_telegram_ids_bigint
Revises:
Create Date: 2026-09-25
"""

from alembic import op
import sqlalchemy as sa


revision = "20260925_telegram_ids_bigint"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if "scans" not in inspector.get_table_names():
        return

    columns = {column["name"]: column for column in inspector.get_columns("scans")}

    for name in ("telegram_chat_id", "telegram_user_id", "telegram_message_id"):
        column = columns.get(name)
        if column is not None and not isinstance(column["type"], sa.BigInteger):
            op.alter_column(
                "scans",
                name,
                existing_type=sa.Integer(),
                type_=sa.BigInteger(),
                existing_nullable=True,
            )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if "scans" not in inspector.get_table_names():
        return

    columns = {column["name"]: column for column in inspector.get_columns("scans")}

    for name in ("telegram_chat_id", "telegram_user_id", "telegram_message_id"):
        column = columns.get(name)
        if column is not None and isinstance(column["type"], sa.BigInteger):
            op.alter_column(
                "scans",
                name,
                existing_type=sa.BigInteger(),
                type_=sa.Integer(),
                existing_nullable=True,
            )
