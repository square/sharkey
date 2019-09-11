-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
ALTER TABLE hostkeys
ADD COLUMN cert_type ENUM('host_cert', 'user_cert') NOT NULL;
UPDATE hostkeys SET cert_type = 'host_cert';
CREATE INDEX idx_hostkeys_cert_type ON hostkeys(cert_type);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
DROP INDEX idx_hostkeys_cert_type ON hostkeys;
ALTER TABLE hostkeys DROP COLUMN cert_type;
