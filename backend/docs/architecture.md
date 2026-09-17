# Architecture & Design Document: Change Management Foundation Layer (Revised)

This document outlines the architectural foundation for the **Enterprise Compliance Automation Platform** (Phase 1), designed around **SOC 2 CC8.1 Change Management** requirements.

---

## 1. Compliance Architecture Flow

The foundation decouples compliance rules from connector logic, ensuring the platform is completely vendor-neutral and deterministic:

```
[SOC 2 CC8.1 Framework]
         │
         ▼
 [Control Library] (Internal Controls e.g. CM-CONTROL-01)
         │
         ▼
  [Check Library] (Config-driven Specs e.g. CM-001)
         │
         ▼
[Common Change Data Model] (Vendor-neutral Domain schemas)
         │
         ▼
[Relational Database Schema] (PostgreSQL/SQLAlchemy tables)
         │
         ▼
[Connector Contracts] (BaseConnector APIs e.g. GitHub/Jira)
```

### 1.2 Platform Ingestion and Runtime Architecture Flow

The runtime ingestion, evaluation, and evidence processing pipeline is structured as follows:

```mermaid
flowchart TD
    GitHub[GitHub API / Webhooks] --> API[GitHub API Sync]
    GitHub --> Webhook[Webhook Receiver]
    
    API -->|Connector| Collector[Collectors: PRs/Reviews/Commits/Runs/Deploys]
    Webhook -->|HMAC Verified| WebhookReceiver[Webhook Event Ingestion]
    
    Collector -->|Persist Raw Events| MongoDB[(MongoDB raw_events)]
    WebhookReceiver -->|Deduplicate & Persist| MongoDB
    
    MongoDB -->|Trigger Async| BackgroundTask[FastAPI BackgroundTasks]
    BackgroundTask -->|Normalize| Normalization[Normalization GitHub to CCDM]
    Normalization -->|Update User Profiles| IdentityResolution[Identity Resolution]
    IdentityResolution -->|Link Commits & Deploys| ChangeCorrelation[Change Correlation]
    
    ChangeCorrelation -->|Store Entities| PostgreSQL[(PostgreSQL / CCDM)]
    
    PostgreSQL -->|Evaluate Rules| EvalEngine[Compliance Evaluation Engine]
    
    EvalEngine -->|Result: PASS| CheckPass[Pass Status]
    EvalEngine -->|Result: FAIL| CheckFail[Fail Status]
    EvalEngine -->|Result: INSUFFICIENT_DATA| CheckMissing[Insufficient Data Status]
    
    CheckPass -->|No Finding / Resolve Existing| Evidence[Evidence & Audit Service]
    CheckFail -->|Generate Open Finding| Finding[Finding]
    Finding -->|Jira Task| Remediation[Remediation Task]
    Remediation -->|Trigger Recheck| Recheck[Recheck Evaluation]
    Recheck -->|PASS: Auto-resolve| CheckPass
    Recheck -->|FAIL: Keep Open| CheckFail
    CheckMissing -->|Audit evidence gap| Evidence
```

---

## 2. Project Folder Structure

The project code is structured as follows:

```
backend/
├── app/
│   ├── core/                  # Configurations, global settings
│   │   ├── config.py          # Environment settings
│   ├── domain/                # Pure domain models (Pydantic / Interfaces)
│   │   ├── frameworks/        # CC8.1 framework models
│   │   ├── controls/          # Control library definitions
│   │   │   ├── models.py      # Control schemas
│   │   │   └── library.json   # 11 seed control definitions
│   │   ├── checks/            # Compliance checks definitions
│   │   │   ├── models.py      # Check schemas
│   │   │   └── library.json   # 15 automation check definitions
│   │   ├── changes/           # Common Change Model domain entities
│   │   ├── identity/          # Users and third-party identity link schemas
│   │   ├── evidence/          # Evidence storage contracts & schemas
│   │   ├── findings/          # Compliance findings schemas
│   │   ├── exceptions/        # Policy exception schemas
│   │   └── raw/               # MongoDB raw event schemas
│   ├── db/                    # Session management and engine settings
│   │   ├── base.py            # SQLAlchemy Base & Mixins
│   │   ├── postgres.py        # Postgres connection pooling
│   │   └── mongodb.py         # MongoDB connection helpers
│   ├── models/                # SQLAlchemy ORM models mapping to tables
│   │   ├── orm.py             # Table columns & relationships definitions
│   └── connectors/            # Base interfaces for data collection
│       └── contract.py        # BaseConnector contract & structures
├── migrations/                # Alembic versioned migration histories
└── tests/                     # Unit test suite verifying domain, database, contracts
```

---

## 3. Entity Relationship Diagram (ERD)

The following diagram illustrates the relational database schema implemented in PostgreSQL:

```mermaid
erDiagram
    frameworks {
        string framework_id PK
        string name
        string description
        string version
        string authority
        string status
    }
    controls {
        string control_id PK
        string framework_id FK
        string criterion
        string name
        string objective
        string description
        string lifecycle_stage
        string applicability
        json evidence_requirements
        string status
        string version
        datetime effective_from
        datetime effective_until
        datetime created_at
        datetime updated_at
    }
    compliance_checks {
        string check_id PK
        string control_id FK
        string name
        string description
        string category
        string severity
        string lifecycle_stage
        json required_data
        json evaluation_logic
        json evidence_requirements
        string remediation_guidance
        string applicability
        json result_types
        string status
        string version
        datetime effective_from
        datetime effective_until
    }
    users {
        string internal_user_id PK
        string tenant_id
        string name
        string email
        string role
        string status
    }
    identity_links {
        int id PK
        string internal_user_id FK
        string tenant_id "Unique constraint with source, external_user_id"
        string source
        string external_user_id
        string external_username
        string external_reference
        string status
    }
    changes {
        string change_id PK
        string tenant_id
        string external_id
        string source
        string title
        string description
        string change_type
        string requester_id FK
        string owner_id FK
        string risk_level
        string environment_id FK
        string application_id FK
        string status
        datetime planned_start
        datetime planned_end
        datetime implemented_at
        datetime completed_at
        datetime created_at
        datetime updated_at
    }
    authorizations {
        string authorization_id PK
        string tenant_id
        string change_id FK
        string authorized_by FK
        string status
        datetime authorized_at
        string justification
        string source
    }
    approvals {
        string approval_id PK
        string tenant_id
        string change_id FK
        string approver_id FK
        string role
        string decision
        datetime approved_at
        string source
    }
    tests {
        string test_id PK
        string tenant_id
        string change_id FK
        string source
        string pipeline_id
        string commit_id
        string test_type
        string status
        datetime started_at
        datetime completed_at
        string evidence_reference
    }
    deployments {
        string deployment_id PK
        string tenant_id
        string change_id FK "nullable"
        string application_id FK
        string environment_id FK
        string repository_id FK
        string version
        string commit_id
        string deployed_by FK
        datetime deployed_at
        string status
        string source
    }
    evidence_metadata {
        string evidence_id PK
        string tenant_id
        string change_id FK "nullable"
        string source
        string source_record_id
        string evidence_type
        string description
        string hash
        string storage_reference
        datetime collected_at
        datetime created_at
    }
    check_result_evidence_association {
        string result_id PK, FK
        string evidence_id PK, FK
    }
    findings {
        string finding_id PK
        string tenant_id
        string check_id FK
        string control_id FK
        string change_id FK "nullable"
        string severity
        string title
        string description
        string status
        datetime resolved_at
        datetime created_at
        datetime updated_at
    }
    remediation_tasks {
        string task_id PK
        string tenant_id
        string finding_id FK
        string title
        string description
        string owner
        string priority
        datetime due_date
        string status
        datetime resolved_at
        datetime created_at
        datetime updated_at
    }
    exceptions {
        string exception_id PK
        string tenant_id
        string control_id FK
        string change_id FK "nullable"
        string requested_by FK
        string approved_by FK
        string justification
        datetime valid_from
        datetime valid_until
        string status
    }
    check_results {
        string result_id PK
        string tenant_id
        string check_id FK
        string change_id FK
        string result
        string rule_version
        json evaluation_inputs
        json details
        datetime evaluated_at
    }
    connector_accounts {
        string account_id PK
        string tenant_id
        string connector_id FK
        string name
        string auth_type
        json config
        string status
    }
    connectors {
        string connector_id PK
        string name
        string type
        string status
    }
    sync_runs {
        string sync_run_id PK
        string account_id FK
        string sync_type
        string status
        int records_synced
        datetime started_at
        datetime completed_at
        string error_message
    }
    change_relationships {
        int relationship_id PK
        string source_id
        string source_type
        string target_id
        string target_type
        string relationship_type
    }
    audit_logs {
        int log_id PK
        string tenant_id
        string actor_id
        string actor_type
        string action
        string entity_type
        string entity_id
        json details
        datetime timestamp
        string event_id
        string previous_hash
        string event_hash
        int sequence_number "Unique constraint with tenant_id"
    }

    frameworks ||--o{ controls : references
    controls ||--o{ compliance_checks : implements
    controls ||--o{ findings : triggers
    controls ||--o{ exceptions : bypasses
    compliance_checks ||--o{ check_results : generates
    compliance_checks ||--o{ findings : results_in
    users ||--o{ identity_links : links
    changes ||--o{ authorizations : has
    changes ||--o{ approvals : requires
    changes ||--o{ tests : validates
    changes ||--o{ deployments : deploys
    changes ||--o{ evidence_metadata : records
    changes ||--o{ findings : maps_to
    changes ||--o{ exceptions : allows
    changes ||--o{ check_results : results
    check_results ||--o{ check_result_evidence_association : associates
    evidence_metadata ||--o{ check_result_evidence_association : associates
    connectors ||--o{ connector_accounts : houses
    connector_accounts ||--o{ sync_runs : executes
    findings ||--o{ remediation_tasks : creates
```

---

## 4. Architectural Rules and Security Clarifications

### 4.1 Tenancy boundaries
All transactional and identity tables contain a `tenant_id` column. This enables multi-tenant SaaS architecture in later phases. All compliance engine queries must filter by `tenant_id` to prevent cross-tenant data leaks.
- **Identity Links**: Enforces a database uniqueness constraint `uq_identity_link_tenant_source_ext_id` on `(tenant_id, source, external_user_id)`. This ensures that a single external ID (e.g. Github account or Jira user) cannot map to multiple users within the same tenant.

### 4.2 Connector Account Security & Credentials
The `config` payload inside `connector_accounts` MUST NOT store raw authentication tokens (such as GitHub personal access tokens or Jira passwords) in production.
- **Production**: Config stores a reference ARN or path pointer (e.g. `/secrets/tenant-abc/github-token` or AWS Secret Manager ARN). The Collector engine in Phase 2 is responsible for resolving the actual token dynamically.
- **Local Dev/Testing**: Environmental credentials can be used dynamically using `.env`.

### 4.3 Database Immutability & Verifiability
- **MongoDB raw_events**: The SHA-256 payload hash acts as an **integrity verification** mechanism. It ensures that collected events are not modified after ingestion. Tamper-evident storage and write-once-read-many (WORM) storage configurations (e.g., S3 Object Lock) are left for later integration.
- **Audit Logs**: The table contains `previous_hash` and `event_hash` columns. During write-operations, each log entry computes a SHA-256 hash over its contents and the preceding row's hash. 
  - **Ordering rule**: Enforced via a unique constraint `uq_audit_log_tenant_seq` on `(tenant_id, sequence_number)` alongside timestamps. This sequence number guarantees a deterministic ordering of log verification, resolving any ambiguity under concurrent events.

### 4.4 Traceability and Evidence Cardinality
- All deployments must be linked to a target application, environment, repository, and git commit hash. If `change_id` is null, the deployment is marked as an **unauthorized bypass change** and triggers a `CM-014` finding.
- Junction mappings are bridged via `change_relationships` using strictly controlled `EntityType` and `RelationshipType` enums.
- **Evidence Cardinality**: Programmatic evaluations represented by `check_results` are linked to multiple evidence items via the junction table `check_result_evidence_association` rather than a one-to-one link. This allows evaluations like `CM-005` (Testing before deployment) to bundle testing pipeline reports, git commit hashes, and CD logs as joint proof.
