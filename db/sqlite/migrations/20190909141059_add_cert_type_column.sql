-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
-- cert_type = 2 means that host cert is the default
-- Aee storage/sqlite.go for more details
ALTER TABLE hostkeys
ADD COLUMN cert_type INTEGER NOT NULL DEFAULT 2;
UPDATE hostkeys SET cert_type = 2;
CREATE INDEX idx_hostkeys_cert_type ON hostkeys(cert_type);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
-- It's not possible to drop a column in SQLite
DROP INDEX idx_hostkeys_cert_type;
