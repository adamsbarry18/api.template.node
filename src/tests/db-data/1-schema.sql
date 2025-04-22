DROP TABLE IF EXISTS `user`;
CREATE TABLE `user` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `uid` VARCHAR(36) DEFAULT NULL,
  `email` VARCHAR(100) NOT NULL,
  `password` VARCHAR(255) NOT NULL,
  `name` VARCHAR(200),
  `surname` VARCHAR(200),
  `level` INT DEFAULT 1,
  `internal_level` INT DEFAULT 1,
  `internal` TINYINT(1) DEFAULT 0,
  `color` VARCHAR(10),
  `password_status` VARCHAR(20) DEFAULT 'ACTIVE',
  `password_time` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `preferences` JSON,
  `authorisation_overrides` VARCHAR(500),
  `permissions_expire_at` TIMESTAMP NULL DEFAULT NULL,
  `created_time` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_time` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `deleted_time` TIMESTAMP NULL DEFAULT NULL,
  UNIQUE KEY `uid` (`uid`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB AUTO_INCREMENT=235 DEFAULT CHARSET=utf8;
