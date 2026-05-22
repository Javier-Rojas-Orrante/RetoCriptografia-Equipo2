CREATE TABLE roles (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    code VARCHAR(50) NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL
);

CREATE TABLE users (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    email VARCHAR(255) NOT NULL UNIQUE,
    full_name VARCHAR(255) NOT NULL,
    role_id BIGINT NOT NULL,
    status ENUM('pending', 'active', 'revoked', 'expired') NOT NULL DEFAULT 'pending',
    certificate_serial VARCHAR(128) NULL,
    certificate_pem TEXT NULL,
    certificate_not_before DATETIME NULL,
    certificate_not_after DATETIME NULL,
    p12_path VARCHAR(255) NULL,
    end_date DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_users_role FOREIGN KEY (role_id) REFERENCES roles(id)
);

CREATE TABLE permissions (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL,
    UNIQUE KEY uniq_permissions_resource_action (resource, action)
);

CREATE TABLE role_permissions (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    role_id BIGINT NOT NULL,
    permission_id BIGINT NOT NULL,
    UNIQUE KEY uniq_role_permissions (role_id, permission_id),
    CONSTRAINT fk_role_permissions_role FOREIGN KEY (role_id) REFERENCES roles(id),
    CONSTRAINT fk_role_permissions_permission FOREIGN KEY (permission_id) REFERENCES permissions(id)
);

CREATE TABLE audit_logs (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    event_type VARCHAR(80) NOT NULL,
    actor_user_id BIGINT NULL,
    target_user_id BIGINT NULL,
    action VARCHAR(80) NOT NULL,
    resource VARCHAR(120) NULL,
    result ENUM('success', 'failure') NOT NULL,
    metadata_json JSON NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE documents (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    folio VARCHAR(255) NOT NULL,
    folio_lookup VARCHAR(80) UNIQUE,
    title VARCHAR(255) NOT NULL,
    document_type VARCHAR(100) NOT NULL,
    document_hash VARCHAR(255) NOT NULL,
    signature TEXT NOT NULL,
    signer_user_id BIGINT NOT NULL,
    certificate_serial VARCHAR(255) NOT NULL,
    certificate_pem_snapshot TEXT NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'signed',
    status_lookup VARCHAR(80),
    issued_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NULL,
    revoked_at DATETIME NULL,
    revocation_reason TEXT NULL,
    original_filename VARCHAR(255) NULL,
    file_size INT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_documents_signer FOREIGN KEY (signer_user_id) REFERENCES users(id)
);

CREATE TABLE document_verifications (
    id BIGINT PRIMARY KEY AUTO_INCREMENT,
    document_id BIGINT NULL,
    folio_entered VARCHAR(255) NULL,
    uploaded_hash VARCHAR(255) NULL,
    result VARCHAR(50) NOT NULL,
    ip_address VARCHAR(100) NULL,
    user_agent TEXT NULL,
    verified_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_verifications_document FOREIGN KEY (document_id) REFERENCES documents(id)
);
