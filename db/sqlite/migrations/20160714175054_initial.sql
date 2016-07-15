-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE hostkeys(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  hostname VARCHAR(255) NOT NULL UNIQUE,
  pubkey BLOB NOT NULL
);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
DROP TABLE hostkeys;
