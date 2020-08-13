-- +goose Up
-- SQL in this section is executed when the migration is applied.
CREATE TABLE github_user_mappings(
  sso_identity VARCHAR(255) PRIMARY KEY NOT NULL UNIQUE,
  github_username VARCHAR(255) NOT NULL UNIQUE
);

-- +goose Down
-- SQL in this section is executed when the migration is rolled back.
DROP TABLE github_user_mappings;