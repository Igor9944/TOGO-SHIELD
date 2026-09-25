"""Change Telegram identifiers from INTEGER to BIGINT.

Revision ID: 20260925_telegram_ids_bigint
Revises: 0001
Create Date: 2026-09-25
"""

from alembic import op
import sqlalchemy as sa


revision = "20260925_telegram_ids_bigint"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if "scans" not in inspector.get_table_names():
        return

    columns = {column["name"]: column for column in inspector.get_columns("scans")}

    names = ("telegram_chat_id", "telegram_user_id", "telegram_message_id")
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("scans") as batch_op:
            for name in names:
                column = columns.get(name)
                if column is not None and not isinstance(column["type"], sa.BigInteger):
                    batch_op.alter_column(name, existing_type=sa.Integer(), type_=sa.BigInteger(), existing_nullable=True)
        return
    for name in names:
        column = columns.get(name)
        if column is not None and not isinstance(column["type"], sa.BigInteger):
            op.alter_column("scans", name, existing_type=sa.Integer(), type_=sa.BigInteger(), existing_nullable=True)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if "scans" not in inspector.get_table_names():
        return

    columns = {column["name"]: column for column in inspector.get_columns("scans")}

    names = ("telegram_chat_id", "telegram_user_id", "telegram_message_id")
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("scans") as batch_op:
            for name in names:
                column = columns.get(name)
                if column is not None and isinstance(column["type"], sa.BigInteger):
                    batch_op.alter_column(name, existing_type=sa.BigInteger(), type_=sa.Integer(), existing_nullable=True)
        return
    for name in names:
        column = columns.get(name)
        if column is not None and isinstance(column["type"], sa.BigInteger):
            op.alter_column("scans", name, existing_type=sa.BigInteger(), type_=sa.Integer(), existing_nullable=True)
