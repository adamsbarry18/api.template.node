SET FOREIGN_KEY_CHECKS = 0;

-- -----------------------------------------------------
-- Table `user` (Fournie et adaptée)
-- -----------------------------------------------------
DROP TABLE IF EXISTS `user`;

CREATE TABLE `user` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `uid` VARCHAR(36) DEFAULT NULL,
    `email` VARCHAR(100) NOT NULL,
    `password` VARCHAR(255) NOT NULL,
    `first_name` VARCHAR(200) DEFAULT NULL,
    `last_name` VARCHAR(200) DEFAULT NULL,
    `level` INT DEFAULT 1,
    `internal_level` INT DEFAULT 1,
    `internal` TINYINT(1) DEFAULT 0,
    `color` VARCHAR(10) DEFAULT NULL,
    `password_status` ENUM('ACTIVE', 'VALIDATING', 'EXPIRED') DEFAULT 'ACTIVE',
    `password_time` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `preferences` JSON DEFAULT NULL,
    `authorisation_overrides` VARCHAR(500) DEFAULT NULL,
    `permissions_expire_at` TIMESTAMP NULL DEFAULT NULL,
    `is_active` TINYINT(1) DEFAULT 1,
    `created_time` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    `updated_time` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    `deleted_time` TIMESTAMP NULL DEFAULT NULL,
    `google_id` VARCHAR(255) DEFAULT NULL,
    UNIQUE KEY `uid_unique` (`uid`),
    UNIQUE KEY `email_unique` (`email`),
    UNIQUE KEY `google_id_unique` (`google_id`)
) ENGINE = InnoDB AUTO_INCREMENT = 1 DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- Réactiver les vérifications de clés étrangères
SET FOREIGN_KEY_CHECKS = 1;
