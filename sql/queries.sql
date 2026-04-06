-- name: AddNode :one
INSERT INTO nodes (
    uuid,
    name,
    base_uri
) VALUES (
    @uuid,
    @name,
    @base_uri
) RETURNING *;

-- name: UpdateNode :one
UPDATE nodes SET
    name = @name,
    base_uri = @base_uri
WHERE uuid = @uuid
RETURNING *;

-- name: RemoveNode :execrows
DELETE FROM nodes WHERE id = @id;

-- name: GetNodes :many
SELECT * FROM nodes;

-- name: GetNodeByUUID :one
SELECT * FROM nodes
WHERE uuid = @uuid;

-- name: AddUser :one
INSERT INTO users (
    uuid,
    description,
    scopes,
    fee,
    is_banned
) VALUES (
    @uuid,
    @description,
    @scopes,
    @fee,
    FALSE
) RETURNING *;

-- name: GetUsers :many
SELECT * FROM users;

-- name: GetUser :one
SELECT * FROM users
WHERE uuid = @uuid;

-- name: UpdateUser :one
UPDATE users SET
    description = @description,
    scopes = @scopes,
    fee = @fee
WHERE uuid = @uuid
RETURNING *;

-- name: BanUser :one
UPDATE users SET
    is_banned = @banned
WHERE uuid = @uuid
RETURNING *;

-- name: UpdateUserPaidUntil :one
UPDATE users SET
    paid_until = @paid_until
WHERE uuid = @uuid
RETURNING *;

-- name: IncrementUserLoginVersion :one
UPDATE users SET
    login_token_version = login_token_version + 1
WHERE
    uuid = @uuid
RETURNING *;

-- name: IncrementUserRefreshVersion :one
UPDATE users SET
    refresh_token_version = refresh_token_version + 1
WHERE
    uuid = @uuid
RETURNING *;

-- name: GetUserAndUpdateForLogin :one
UPDATE users SET
    login_token_version = login_token_version +1
WHERE
    uuid = @uuid
    AND login_token_version = @current_login_version
RETURNING *;
