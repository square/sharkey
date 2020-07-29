-- +goose Up
-- SQL in this section is executed when the migration is applied.
CREATE TABLE github(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ssoIdentity VARCHAR(255) NOT NULL UNIQUE,
  githubUser VARCHAR(255) NOT NULL UNIQUE
);

-- +goose Down
-- SQL in this section is executed when the migration is rolled back.
DROP TABLE github;