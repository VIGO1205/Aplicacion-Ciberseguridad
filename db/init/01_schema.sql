-- SOC-Lite · Esquema PostgreSQL 15+
-- Generado desde los modelos SQLAlchemy. No editar a mano sin actualizar modelos.

BEGIN;

CREATE TABLE assets (
	id UUID NOT NULL, 
	hostname VARCHAR(150) NOT NULL, 
	ip_address VARCHAR(45), 
	criticality VARCHAR(8) NOT NULL, 
	owner VARCHAR(150) NOT NULL, 
	environment VARCHAR(60) NOT NULL, 
	operating_system VARCHAR(100) NOT NULL, 
	tags JSONB NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (hostname), 
	CONSTRAINT criticality CHECK (criticality IN ('critical', 'high', 'medium', 'low'))
);

CREATE INDEX ix_assets_ip_address ON assets (ip_address);

CREATE TABLE permissions (
	id UUID NOT NULL, 
	code VARCHAR(80) NOT NULL, 
	module VARCHAR(40) NOT NULL, 
	description VARCHAR(255) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (code)
);


CREATE TABLE roles (
	id UUID NOT NULL, 
	name VARCHAR(50) NOT NULL, 
	description VARCHAR(255) NOT NULL, 
	is_system BOOLEAN NOT NULL, 
	color VARCHAR(20) NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (name)
);


CREATE TABLE role_permissions (
	role_id UUID NOT NULL, 
	permission_id UUID NOT NULL, 
	PRIMARY KEY (role_id, permission_id), 
	FOREIGN KEY(role_id) REFERENCES roles (id) ON DELETE CASCADE, 
	FOREIGN KEY(permission_id) REFERENCES permissions (id) ON DELETE CASCADE
);


CREATE TABLE users (
	id UUID NOT NULL, 
	email VARCHAR(255) NOT NULL, 
	full_name VARCHAR(150) NOT NULL, 
	hashed_password VARCHAR(255) NOT NULL, 
	role_id UUID NOT NULL, 
	is_active BOOLEAN NOT NULL, 
	job_title VARCHAR(120) NOT NULL, 
	department VARCHAR(120) NOT NULL, 
	phone VARCHAR(40) NOT NULL, 
	last_login_at TIMESTAMP WITH TIME ZONE, 
	password_changed_at TIMESTAMP WITH TIME ZONE, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(role_id) REFERENCES roles (id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX ix_users_email ON users (email);

CREATE TABLE alerts (
	id UUID NOT NULL, 
	external_id VARCHAR(180), 
	fingerprint VARCHAR(64) NOT NULL, 
	source VARCHAR(40) NOT NULL, 
	title VARCHAR(300) NOT NULL, 
	description TEXT NOT NULL, 
	rule_id VARCHAR(40), 
	rule_level INTEGER NOT NULL, 
	severity VARCHAR(8) NOT NULL, 
	status VARCHAR(14) NOT NULL, 
	source_ip VARCHAR(45), 
	destination_ip VARCHAR(45), 
	hostname VARCHAR(150), 
	agent_name VARCHAR(150), 
	username VARCHAR(150), 
	asset_id UUID, 
	assigned_to_id UUID, 
	mitre_techniques JSONB NOT NULL, 
	tags JSONB NOT NULL, 
	raw_payload JSONB NOT NULL, 
	received_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	closed_at TIMESTAMP WITH TIME ZONE, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_alerts_fingerprint UNIQUE (fingerprint), 
	CONSTRAINT ck_alerts_rule_level CHECK (rule_level BETWEEN 0 AND 15), 
	CONSTRAINT severity CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')), 
	CONSTRAINT alert_status CHECK (status IN ('pending', 'triaging', 'triaged', 'escalated', 'false_positive', 'closed')), 
	FOREIGN KEY(asset_id) REFERENCES assets (id) ON DELETE SET NULL, 
	FOREIGN KEY(assigned_to_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX ix_alerts_source ON alerts (source);
CREATE INDEX ix_alerts_source_ip ON alerts (source_ip);
CREATE INDEX ix_alerts_source_received ON alerts (source, received_at);
CREATE INDEX ix_alerts_status_received ON alerts (status, received_at);
CREATE INDEX ix_alerts_received_at ON alerts (received_at);
CREATE INDEX ix_alerts_hostname ON alerts (hostname);
CREATE INDEX ix_alerts_fingerprint ON alerts (fingerprint);
CREATE INDEX ix_alerts_status ON alerts (status);
CREATE INDEX ix_alerts_external_id ON alerts (external_id);
CREATE INDEX ix_alerts_severity_received ON alerts (severity, received_at);
CREATE INDEX ix_alerts_severity ON alerts (severity);

CREATE TABLE audit_log (
	id UUID NOT NULL, 
	user_id UUID, 
	actor_email VARCHAR(255) NOT NULL, 
	actor_role VARCHAR(50) NOT NULL, 
	event_type VARCHAR(40) NOT NULL, 
	module VARCHAR(40) NOT NULL, 
	action VARCHAR(160) NOT NULL, 
	direction VARCHAR(8), 
	entity_type VARCHAR(40), 
	entity_id VARCHAR(80), 
	description VARCHAR(500) NOT NULL, 
	method VARCHAR(10), 
	path VARCHAR(300), 
	status_code INTEGER, 
	ip_address VARCHAR(45), 
	user_agent VARCHAR(300), 
	request_id VARCHAR(64), 
	detail JSONB NOT NULL, 
	duration_ms INTEGER, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX ix_audit_log_request_id ON audit_log (request_id);
CREATE INDEX ix_audit_event_created ON audit_log (event_type, created_at);
CREATE INDEX ix_audit_module_created ON audit_log (module, created_at);
CREATE INDEX ix_audit_log_module ON audit_log (module);
CREATE INDEX ix_audit_log_created_at ON audit_log (created_at);
CREATE INDEX ix_audit_user_created ON audit_log (user_id, created_at);

CREATE TABLE refresh_tokens (
	id UUID NOT NULL, 
	user_id UUID NOT NULL, 
	jti VARCHAR(64) NOT NULL, 
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	revoked_at TIMESTAMP WITH TIME ZONE, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX ix_refresh_tokens_user_id ON refresh_tokens (user_id);
CREATE UNIQUE INDEX ix_refresh_tokens_jti ON refresh_tokens (jti);

CREATE TABLE reports (
	id UUID NOT NULL, 
	name VARCHAR(200) NOT NULL, 
	report_type VARCHAR(11) NOT NULL, 
	format VARCHAR(4) NOT NULL, 
	period_start TIMESTAMP WITH TIME ZONE NOT NULL, 
	period_end TIMESTAMP WITH TIME ZONE NOT NULL, 
	filters JSONB NOT NULL, 
	file_name VARCHAR(255) NOT NULL, 
	size_bytes INTEGER NOT NULL, 
	generated_by_id UUID, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT report_type CHECK (report_type IN ('operational', 'management', 'audit')), 
	CONSTRAINT report_format CHECK (format IN ('pdf', 'docx', 'xlsx')), 
	FOREIGN KEY(generated_by_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE INDEX ix_reports_created_at ON reports (created_at);

CREATE TABLE enrichment_data (
	id UUID NOT NULL, 
	alert_id UUID NOT NULL, 
	provider VARCHAR(40) NOT NULL, 
	indicator VARCHAR(190) NOT NULL, 
	indicator_type VARCHAR(30) NOT NULL, 
	status VARCHAR(30) NOT NULL, 
	risk_score FLOAT, 
	summary VARCHAR(500) NOT NULL, 
	payload JSONB NOT NULL, 
	fetched_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	expires_at TIMESTAMP WITH TIME ZONE, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_enrichment_alert_provider_indicator UNIQUE (alert_id, provider, indicator), 
	FOREIGN KEY(alert_id) REFERENCES alerts (id) ON DELETE CASCADE
);

CREATE INDEX ix_enrichment_data_alert_id ON enrichment_data (alert_id);

CREATE TABLE incidents (
	id UUID NOT NULL, 
	code VARCHAR(30) NOT NULL, 
	alert_id UUID, 
	title VARCHAR(300) NOT NULL, 
	description TEXT NOT NULL, 
	severity VARCHAR(8) NOT NULL, 
	status VARCHAR(13) NOT NULL, 
	owner_id UUID, 
	containment_actions TEXT NOT NULL, 
	ticket_external_id VARCHAR(80), 
	sla_due_at TIMESTAMP WITH TIME ZONE, 
	opened_at TIMESTAMP WITH TIME ZONE NOT NULL, 
	closed_at TIMESTAMP WITH TIME ZONE, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	updated_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (alert_id), 
	FOREIGN KEY(alert_id) REFERENCES alerts (id) ON DELETE SET NULL, 
	CONSTRAINT incident_severity CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')), 
	CONSTRAINT incident_status CHECK (status IN ('open', 'investigating', 'contained', 'resolved', 'closed')), 
	FOREIGN KEY(owner_id) REFERENCES users (id) ON DELETE SET NULL
);

CREATE UNIQUE INDEX ix_incidents_code ON incidents (code);
CREATE INDEX ix_incidents_status_severity ON incidents (status, severity);

CREATE TABLE triage_results (
	id UUID NOT NULL, 
	alert_id UUID NOT NULL, 
	verdict VARCHAR(14) NOT NULL, 
	recommended_severity VARCHAR(8) NOT NULL, 
	confidence FLOAT NOT NULL, 
	risk_score INTEGER NOT NULL, 
	summary TEXT NOT NULL, 
	reasoning TEXT NOT NULL, 
	recommended_actions JSONB NOT NULL, 
	mitre_techniques JSONB NOT NULL, 
	should_escalate BOOLEAN NOT NULL, 
	false_positive_reason TEXT, 
	engine VARCHAR(40) NOT NULL, 
	model_name VARCHAR(100) NOT NULL, 
	prompt_version VARCHAR(30) NOT NULL, 
	latency_ms INTEGER NOT NULL, 
	tokens_used INTEGER NOT NULL, 
	raw_response JSONB NOT NULL, 
	created_at TIMESTAMP WITH TIME ZONE DEFAULT now() NOT NULL, 
	PRIMARY KEY (id), 
	CONSTRAINT uq_triage_alert UNIQUE (alert_id), 
	FOREIGN KEY(alert_id) REFERENCES alerts (id) ON DELETE CASCADE, 
	CONSTRAINT verdict CHECK (verdict IN ('true_positive', 'false_positive', 'suspicious', 'benign')), 
	CONSTRAINT recommended_severity CHECK (recommended_severity IN ('critical', 'high', 'medium', 'low', 'info'))
);

CREATE INDEX ix_triage_results_alert_id ON triage_results (alert_id);
CREATE INDEX ix_triage_results_created_at ON triage_results (created_at);

CREATE TABLE osticket_ticket_links (
	alert_id UUID NOT NULL,
	ticket_id INTEGER NOT NULL,
	ticket_number VARCHAR(20) NOT NULL,
	status_state VARCHAR(16) NOT NULL,
	status_name VARCHAR(60) NOT NULL,
	closed_by_ticket BOOLEAN NOT NULL,
	previous_alert_status VARCHAR(20),
	applied_closed_at TIMESTAMP WITH TIME ZONE,
	last_synced_at TIMESTAMP WITH TIME ZONE NOT NULL,
	PRIMARY KEY (alert_id),
	UNIQUE (ticket_id),
	FOREIGN KEY(alert_id) REFERENCES alerts (id) ON DELETE CASCADE
);

COMMIT;

-- Datos semilla: la aplicación los carga de forma idempotente al iniciar
-- con AUTO_SEED=true o mediante: python -m app.seed
