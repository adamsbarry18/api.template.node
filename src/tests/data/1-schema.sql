CREATE TABLE "user" (
  id SERIAL PRIMARY KEY,
  uid VARCHAR(36) UNIQUE,
  email VARCHAR(100) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  name VARCHAR(200),
  surname VARCHAR(200),
  level INT DEFAULT 0,
  internal_level INT DEFAULT 0,
  internal BOOLEAN DEFAULT FALSE,
  color VARCHAR(10),
  password_status VARCHAR(20) DEFAULT 'ACTIVE',
  password_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  preferences JSON,
  authorisation_overrides VARCHAR(500),
  permissions_expire_at TIMESTAMP,
  created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  deleted_time TIMESTAMP,
  owner_id INT,
  last_user_id INT
);

-- Indexes for performance (optional)
CREATE INDEX idx_user_email ON "user"(email);
CREATE INDEX idx_user_uid ON "user"(uid);
