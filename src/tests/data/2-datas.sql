-- Insert an admin user (password: 'AdminTest1!' hashed with bcrypt, adjust hash as needed)
INSERT INTO "user" (
  uid, email, password, name, surname, level, internal_level, internal, color,
  password_status, password_time, preferences, authorisation_overrides, permissions_expire_at,
  created_time, updated_time, owner_id, last_user_id
) VALUES (
  '00000000-0000-0000-0000-000000000001',
  'admin+test@yopmail.com',
  '$2b$10$wq1kQw7n5Qw7n5Qw7n5QwOQw7n5Qw7n5Qw7n5Qw7n5Qw7n5Qw7n5Q', -- replace with a valid bcrypt hash for 'AdminTest1!'
  'Admin',
  'Test',
  5,
  0,
  TRUE,
  '#000000',
  'ACTIVE',
  CURRENT_TIMESTAMP,
  '{"theme":"dark"}',
  NULL,
  NULL,
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP,
  NULL,
  NULL
);
