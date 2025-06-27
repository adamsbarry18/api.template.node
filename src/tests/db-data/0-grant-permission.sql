GRANT ALL PRIVILEGES ON test_db.* TO 'test_user'@'%';
FLUSH PRIVILEGES;
-- Ligne supprimée ou commentée car la table n'existe pas à l'init :
-- UPDATE `user` SET `level` = 5, `internal` = 1 WHERE `id` = 1;
