-- +goose Up
CREATE TABLE nodes (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid     TEXT NOT NULL UNIQUE,
    name     TEXT NOT NULL UNIQUE,
    base_uri TEXT NOT NULL
);
CREATE TABLE users (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid                  TEXT NOT NULL UNIQUE,
    -- For admins.
    description           TEXT NOT NULL,
    -- Comma separated.
    -- Scopes: nodes, users, peers
    scopes                TEXT NOT NULL,
    -- Empty => no charge
    fee                   TEXT NOT NULL,
    paid_until            TIMESTAMP,
    is_banned             BOOLEAN NOT NULL,
    login_token_version   INTEGER NOT NULL DEFAULT 0,
    refresh_token_version INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE new_peer_requests (
    id                     INTEGER PRIMARY KEY AUTOINCREMENT,
    random_id              TEXT NOT NULL,      -- base64 raw url encoded (no padding)
    interface_name         TEXT NOT NULL,      -- zeroed after the peer was created
    requested_at           TIMESTAMP NOT NULL, -- zeroed after the peer was created
    requested_by_user_uuid TEXT,               -- zeroed after the peer was created
    node_id                INTEGER NOT NULL,
    owned_by_user_id       INTEGER NOT NULL,
    status                 TEXT NOT NULL DEFAULT 'pending', -- one of: "pending", "config-requested", "created", "cancelled"

    FOREIGN KEY(node_id) REFERENCES nodes(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,
    FOREIGN KEY(requested_by_user_uuid) REFERENCES users(uuid)
        ON DELETE CASCADE
        ON UPDATE CASCADE,
    FOREIGN KEY(owned_by_user_id) REFERENCES users(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
);

CREATE TABLE request_encryption_keys (
    key0         TEXT,
    key1         TEXT,
    rotate_after TIMESTAMP NOT NULL
);
INSERT INTO request_encryption_keys (
    key0,
    key1,
    rotate_after
) VALUES (NULL, NULL, '1970-01-01');

-- +goose Down
DROP TABLE nodes;
DROP TABLE users;
DROP TABLE new_peer_requests;
DROP TABLE request_encryption_keys;
