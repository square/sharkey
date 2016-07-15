-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
CREATE TABLE hostkeys(
  id INTEGER PRIMARY KEY AUTO_INCREMENT,
  hostname VARCHAR(255) NOT NULL UNIQUE,
  pubkey BLOB NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
DROP TABLE hostkeys;
