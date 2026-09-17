"""Initial scan and compliance schema

Revision ID: 001_initial_scan_schema
Revises: 
Create Date: 2026-09-11 12:40:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '001_initial_scan_schema'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # scan_jobs table
    op.create_table(
        'scan_jobs',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('tenant_id', sa.Integer(), nullable=False, index=True),
        sa.Column('repository_id', sa.String(), nullable=False, index=True),
        sa.Column('repository_name', sa.String(), nullable=False, index=True),
        sa.Column('branch', sa.String(), nullable=False),
        sa.Column('commit_sha', sa.String(), nullable=False, index=True),
        sa.Column('scan_type', sa.String(), default='SAST'),
        sa.Column('status', sa.String(), default='PENDING', index=True),
        sa.Column('scanners', sa.JSON(), nullable=True),
        sa.Column('scanner_versions', sa.JSON(), nullable=True),
        sa.Column('files_scanned', sa.Integer(), default=0),
        sa.Column('rules_executed', sa.Integer(), default=0),
        sa.Column('finding_count', sa.Integer(), default=0),
        sa.Column('raw_result_hash', sa.String(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now())
    )

    # canonical_security_findings table
    op.create_table(
        'canonical_security_findings',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('tenant_id', sa.Integer(), nullable=False, index=True),
        sa.Column('scan_id', sa.String(), sa.ForeignKey('scan_jobs.id'), nullable=False, index=True),
        sa.Column('fingerprint', sa.String(), nullable=False, index=True),
        sa.Column('source', sa.String(), default='scanner'),
        sa.Column('scanner', sa.String(), nullable=False),
        sa.Column('scanner_version', sa.String(), nullable=True),
        sa.Column('source_finding_id', sa.String(), nullable=True),
        sa.Column('source_url', sa.String(), nullable=True),
        sa.Column('repository_id', sa.String(), nullable=False, index=True),
        sa.Column('repository_name', sa.String(), nullable=False),
        sa.Column('branch', sa.String(), nullable=False),
        sa.Column('commit_sha', sa.String(), nullable=False),
        sa.Column('file_path', sa.String(), nullable=False),
        sa.Column('start_line', sa.Integer(), nullable=True),
        sa.Column('end_line', sa.Integer(), nullable=True),
        sa.Column('rule_id', sa.String(), nullable=False, index=True),
        sa.Column('rule_name', sa.String(), nullable=True),
        sa.Column('rule_category', sa.String(), nullable=True),
        sa.Column('title', sa.String(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(), default='MEDIUM'),
        sa.Column('confidence', sa.String(), default='HIGH'),
        sa.Column('cwe', sa.JSON(), nullable=True),
        sa.Column('cve', sa.JSON(), nullable=True),
        sa.Column('owasp_category', sa.JSON(), nullable=True),
        sa.Column('status', sa.String(), default='OPEN', index=True),
        sa.Column('first_seen', sa.DateTime(), default=sa.func.now()),
        sa.Column('last_seen', sa.DateTime(), default=sa.func.now()),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('owner', sa.String(), nullable=True),
        sa.Column('team', sa.String(), nullable=True),
        sa.Column('risk_score', sa.Float(), default=0.0),
        sa.Column('priority', sa.String(), default='P3'),
        sa.Column('remediation', sa.Text(), nullable=True),
        sa.Column('remediation_due_at', sa.DateTime(), nullable=True),
        sa.Column('verification_status', sa.String(), default='UNVERIFIED'),
        sa.Column('evidence_id', sa.String(), nullable=True),
        sa.Column('jira_issue_key', sa.String(), nullable=True, index=True),
        sa.Column('pr_url', sa.String(), nullable=True)
    )

    # scan_evidence table
    op.create_table(
        'scan_evidence',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('tenant_id', sa.Integer(), nullable=False, index=True),
        sa.Column('scan_id', sa.String(), sa.ForeignKey('scan_jobs.id'), nullable=False, index=True),
        sa.Column('scanner', sa.String(), nullable=False),
        sa.Column('scanner_version', sa.String(), nullable=True),
        sa.Column('rule_version', sa.String(), nullable=True),
        sa.Column('repository', sa.String(), nullable=False),
        sa.Column('branch', sa.String(), nullable=False),
        sa.Column('commit_sha', sa.String(), nullable=False),
        sa.Column('files_scanned', sa.Integer(), default=0),
        sa.Column('rules_executed', sa.Integer(), default=0),
        sa.Column('finding_count', sa.Integer(), default=0),
        sa.Column('raw_result_hash', sa.String(), nullable=False),
        sa.Column('result_hash', sa.String(), nullable=False),
        sa.Column('execution_status', sa.String(), nullable=False),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now())
    )

    # compliance_evaluations table
    op.create_table(
        'compliance_evaluations',
        sa.Column('id', sa.String(), primary_key=True),
        sa.Column('tenant_id', sa.Integer(), nullable=False, index=True),
        sa.Column('control_id', sa.String(), nullable=False, index=True),
        sa.Column('evaluation_id', sa.String(), nullable=False, index=True),
        sa.Column('result', sa.String(), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('scan_id', sa.String(), nullable=True, index=True),
        sa.Column('finding_ids', sa.JSON(), nullable=True),
        sa.Column('input_evidence', sa.JSON(), nullable=True),
        sa.Column('evaluator_version', sa.String(), default='1.0.0'),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now())
    )

def downgrade():
    op.drop_table('compliance_evaluations')
    op.drop_table('scan_evidence')
    op.drop_table('canonical_security_findings')
    op.drop_table('scan_jobs')
