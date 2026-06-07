-- Create test database alongside main db
SELECT 'CREATE DATABASE test_authdb'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'test_authdb')\gexec
