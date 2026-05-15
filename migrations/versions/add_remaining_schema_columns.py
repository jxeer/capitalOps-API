"""Add remaining schema columns (users profile, work_orders, risk_flags, portfolios, investors, mfa_codes)

Revision ID: add_remaining_schema_columns
Revises: hash_mfa_codes_and_reset_tokens
Create Date: 2026-05-15

Adds columns that were previously managed via inline ALTER TABLE in app/__init__.py.
All new schema changes go through Alembic migrations only.

Covers:
  users: google_id, profile_type, profile_status, title, organization,
         linked_in_url, bio, profile_image, geographic_focus, investment_stage,
         target_return, check_size_min, check_size_max, risk_tolerance,
         strategic_interest, service_types, geographic_service_area,
         years_of_experience, certifications, average_project_size,
         development_focus, development_type, team_size, portfolio_value,
         password_hash (nullable for Google-only accounts)

  work_orders: description, photo_url, created_at

  risk_flags: resolved_at, created_at

  portfolios: user_id (for user-scoped data isolation)

  investors: user_id (for user-scoped data isolation)

  mfa_codes: failed_attempts (for brute-force protection on MFA verification)
"""

from alembic import op
import sqlalchemy as sa

revision = 'add_remaining_schema_columns'
down_revision = 'hash_mfa_codes_and_reset_tokens'
branch_labels = None
depends_on = None


def upgrade():
    # --- users table: profile and account columns ---
    op.add_column('users', sa.Column('google_id', sa.String(255), nullable=True))
    op.add_column('users', sa.Column('profile_type', sa.String(20), nullable=True))
    op.add_column('users', sa.Column('profile_status', sa.String(20), nullable=True))
    op.add_column('users', sa.Column('title', sa.String(100), nullable=True))
    op.add_column('users', sa.Column('organization', sa.String(200), nullable=True))
    op.add_column('users', sa.Column('linked_in_url', sa.String(500), nullable=True))
    op.add_column('users', sa.Column('bio', sa.Text(), nullable=True))
    op.add_column('users', sa.Column('profile_image', sa.String(500), nullable=True))
    op.add_column('users', sa.Column('geographic_focus', sa.String(200), nullable=True))
    op.add_column('users', sa.Column('investment_stage', sa.String(100), nullable=True))
    op.add_column('users', sa.Column('target_return', sa.String(100), nullable=True))
    op.add_column('users', sa.Column('check_size_min', sa.Numeric(15, 2), nullable=True))
    op.add_column('users', sa.Column('check_size_max', sa.Numeric(15, 2), nullable=True))
    op.add_column('users', sa.Column('risk_tolerance', sa.String(20), nullable=True))
    op.add_column('users', sa.Column('strategic_interest', sa.String(100), nullable=True))
    op.add_column('users', sa.Column('service_types', sa.String(200), nullable=True))
    op.add_column('users', sa.Column('geographic_service_area', sa.String(200), nullable=True))
    op.add_column('users', sa.Column('years_of_experience', sa.String(50), nullable=True))
    op.add_column('users', sa.Column('certifications', sa.Text(), nullable=True))
    op.add_column('users', sa.Column('average_project_size', sa.Numeric(15, 2), nullable=True))
    op.add_column('users', sa.Column('development_focus', sa.String(100), nullable=True))
    op.add_column('users', sa.Column('development_type', sa.String(100), nullable=True))
    op.add_column('users', sa.Column('team_size', sa.Integer(), nullable=True))
    op.add_column('users', sa.Column('portfolio_value', sa.Numeric(15, 2), nullable=True))

    # --- users table: make password_hash nullable for Google-only accounts ---
    op.alter_column('users', 'password_hash', existing_type=sa.String(255), nullable=True)

    # --- work_orders table ---
    op.add_column('work_orders', sa.Column('description', sa.Text(), nullable=True))
    op.add_column('work_orders', sa.Column('photo_url', sa.String(500), nullable=True))
    op.add_column('work_orders', sa.Column('created_at', sa.DateTime(), nullable=True))

    # --- risk_flags table ---
    op.add_column('risk_flags', sa.Column('resolved_at', sa.DateTime(), nullable=True))
    op.add_column('risk_flags', sa.Column('created_at', sa.DateTime(), nullable=True))

    # --- portfolios table: user_id for data isolation ---
    op.add_column('portfolios', sa.Column('user_id', sa.Integer(), nullable=True))
    op.create_foreign_key('fk_portfolios_user_id', 'portfolios', 'users', ['user_id'], ['id'])

    # --- investors table: user_id for data isolation ---
    op.add_column('investors', sa.Column('user_id', sa.Integer(), nullable=True))
    op.create_foreign_key('fk_investors_user_id', 'investors', 'users', ['user_id'], ['id'])

    # --- mfa_codes table: failed_attempts for brute-force protection ---
    op.add_column('mfa_codes', sa.Column('failed_attempts', sa.Integer(), nullable=True))


def downgrade():
    op.drop_column('mfa_codes', 'failed_attempts')
    op.drop_constraint('fk_investors_user_id', 'investors', type_='foreignkey')
    op.drop_column('investors', 'user_id')
    op.drop_constraint('fk_portfolios_user_id', 'portfolios', type_='foreignkey')
    op.drop_column('portfolios', 'user_id')
    op.drop_column('risk_flags', 'created_at')
    op.drop_column('risk_flags', 'resolved_at')
    op.drop_column('work_orders', 'created_at')
    op.drop_column('work_orders', 'photo_url')
    op.drop_column('work_orders', 'description')
    op.alter_column('users', 'password_hash', existing_type=sa.String(255), nullable=False)
    op.drop_column('users', 'portfolio_value')
    op.drop_column('users', 'team_size')
    op.drop_column('users', 'development_type')
    op.drop_column('users', 'development_focus')
    op.drop_column('users', 'average_project_size')
    op.drop_column('users', 'certifications')
    op.drop_column('users', 'years_of_experience')
    op.drop_column('users', 'geographic_service_area')
    op.drop_column('users', 'service_types')
    op.drop_column('users', 'strategic_interest')
    op.drop_column('users', 'risk_tolerance')
    op.drop_column('users', 'check_size_max')
    op.drop_column('users', 'check_size_min')
    op.drop_column('users', 'target_return')
    op.drop_column('users', 'investment_stage')
    op.drop_column('users', 'geographic_focus')
    op.drop_column('users', 'profile_image')
    op.drop_column('users', 'bio')
    op.drop_column('users', 'linked_in_url')
    op.drop_column('users', 'organization')
    op.drop_column('users', 'title')
    op.drop_column('users', 'profile_status')
    op.drop_column('users', 'profile_type')
    op.drop_column('users', 'google_id')