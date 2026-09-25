"""
Ajout des champs de métadonnées de fichier à la table scans.

Champs ajoutés :
- file_name : nom du fichier (nullable)
- file_type : type MIME / extension (nullable)
- file_size : taille en octets (nullable)
- file_sha256 : hash SHA-256 du fichier (nullable)
- extracted_text : texte extrait du fichier (nullable, pour OCR/PDF)
"""
from alembic import op
import sqlalchemy as sa

revision = "0002_file_metadata"
down_revision = "20260925_telegram_ids_bigint"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Colonnes de métadonnées fichier (nullable — compatibles avec les scans existants)
    op.add_column("scans", sa.Column("file_name", sa.String(length=255), nullable=True))
    op.add_column("scans", sa.Column("file_type", sa.String(length=64), nullable=True))
    op.add_column("scans", sa.Column("file_size", sa.BigInteger(), nullable=True))
    op.add_column("scans", sa.Column("file_sha256", sa.String(length=64), nullable=True))
    op.add_column("scans", sa.Column("extracted_text", sa.Text(), nullable=True))

    # Index pour retrouver les scans par fichier
    op.create_index("ix_scans_file_sha256", "scans", ["file_sha256"])


def downgrade() -> None:
    op.drop_index("ix_scans_file_sha256", table_name="scans")
    op.drop_column("scans", "extracted_text")
    op.drop_column("scans", "file_sha256")
    op.drop_column("scans", "file_size")
    op.drop_column("scans", "file_type")
    op.drop_column("scans", "file_name")
