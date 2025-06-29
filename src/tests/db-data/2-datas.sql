
SET FOREIGN_KEY_CHECKS = 0;

-- -----------------------------------------------------
-- Table user
-- -----------------------------------------------------
INSERT INTO `user` (id, email, password, first_name, last_name, level, internal_level, internal, color, password_status, password_time, preferences, authorisation_overrides, permissions_expire_at, is_active, google_id, created_time, updated_time) VALUES 
(1, 'user.test1@example.com', '$2b$10$L0G.mEOfoi02sUuw6SlCC.pMDRcw2qRI01u..e5jrE4S4takXAHae', 'Admin', 'Test', 5, 1, 1, '#000000', 'ACTIVE', CURRENT_TIMESTAMP, '{"theme":"dark"}', NULL, NULL, 1, NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
(2, 'user.test2@example.com', '$2b$10$L0G.mEOfoi02sUuw6SlCC.pMDRcw2qRI01u..e5jrE4S4takXAHae', 'User', 'Test', 3, 1, 1, '#123456', 'ACTIVE', CURRENT_TIMESTAMP, '{"theme":"light"}', NULL, NULL, 1, NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
(3, 'expired.user@example.com', '$2b$10$KWc6fmG0ZMycrHCD/1jZr.X2PZFBlmXe1OkqgwAXu3DOdG4jZzzj2', 'Expired', 'User', 1, 1, 0, '#FF0000', 'EXPIRED', '2000-01-01 00:00:00', '{"theme":"expired"}', NULL, NULL, 1, NULL, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

SET FOREIGN_KEY_CHECKS = 1;