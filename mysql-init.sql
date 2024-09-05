CREATE USER 'admin'@'%' IDENTIFIED WITH 'caching_sha2_password' BY 'pass';
GRANT ALL PRIVILEGES ON sec.* TO 'admin'@'%';
FLUSH PRIVILEGES;
