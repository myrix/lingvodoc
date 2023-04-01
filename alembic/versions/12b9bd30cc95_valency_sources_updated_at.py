"""Valency sources updated_at

Revision ID: 12b9bd30cc95
Revises: be06149acd44
Create Date: 2023-03-29 18:55:53.033319

"""

# revision identifiers, used by Alembic.
revision = '12b9bd30cc95'
down_revision = 'be06149acd44'
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa


def upgrade():

    op.execute('''

        ALTER TABLE valency_source_data
          ADD COLUMN updated_at TIMESTAMP without time zone NOT NULL DEFAULT '1970-01-01 00:00:00';

    ''')


def downgrade():

    op.execute('''

        ALTER TABLE valency_source_data
          DROP COLUMN updated_at;

    ''')

