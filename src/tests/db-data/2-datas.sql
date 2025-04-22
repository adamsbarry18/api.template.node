
INSERT INTO `user` (
  id, email, password, name, surname, level, internal_level, internal, color,
  password_status, password_time, preferences, authorisation_overrides, permissions_expire_at,
  created_time, updated_time
) VALUES (
  1,
  'mabarry2018@gmail.com',
  '$2b$10$mQ1pq0vXmPlo9Y34WMmapeDVBDAF10g6eIGlSzBVAwT.fdn9OqDIa',
  'Admin',
  'Test',
  5,
  1,
  1,
  '#000000',
  'ACTIVE',
  CURRENT_TIMESTAMP,
  '{"theme":"dark"}',
  NULL,
  NULL,
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
);


INSERT INTO `user` (
  id, email, password, name, surname, level, internal_level, internal, color,
  password_status, password_time, preferences, authorisation_overrides, permissions_expire_at,
  created_time, updated_time
) VALUES (
  2,
  'user.test2@example.com',
  '$2b$10$w0bQw8Q1pQw8Qw8Qw8Qw8uQw8Qw8Qw8Qw8Qw8Qw8Qw8Qw8Qw8Qw8', 
  'User',
  'Test',
  3,
  1,
  0,
  '#123456',
  'ACTIVE',
  CURRENT_TIMESTAMP,
  '{"theme":"light"}',
  NULL,
  NULL,
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
);
