-- +goose Up
ALTER TABLE nodes ADD allowed_ips TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE nodes DROP COLUMN allowed_ips;
