-- +goose Up
CREATE TABLE nodes (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid     TEXT NOT NULL UNIQUE,
    name     TEXT NOT NULL UNIQUE,
    base_uri TEXT NOT NULL
);

-- +goose Down
DROP TABLE nodes;
