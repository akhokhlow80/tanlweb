-- +goose Up
CREATE TABLE users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid        TEXT NOT NULL UNIQUE,
    -- For admins.
    description TEXT NOT NULL,
    -- Comma separated.
    -- Scopes: nodes, users, peers
    scopes      TEXT NOT NULL,
    -- Empty => no charge
    fee         TEXT NOT NULL,
    paid_until  TIMESTAMP,
    is_banned   BOOLEAN NOT NULL
);

-- +goose Down
DROP TABLE users;
