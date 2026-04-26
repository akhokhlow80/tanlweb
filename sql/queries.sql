--- ======= Nodes ======= 

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

--- ======= Users ======= 

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

--- ======= Peer requests ======= 

-- name: CreateNewPeerRequest :exec
INSERT INTO new_peer_requests (
    random_id,
    interface_name,
    requested_at,
    requested_by_user_uuid,
    node_id,
    owned_by_user_id
) VALUES (
    @random_id,
    @interface_name,
    @requested_at,
    @requested_by_user_uuid,
    @node_id,
    @owned_by_user_id
);

-- name: GetNewPeerRequests :many
SELECT
    new_peer_requests.random_id,
    new_peer_requests.requested_at,
    new_peer_requests.requested_by_user_uuid,
    new_peer_requests.interface_name,
    new_peer_requests.status,
    nodes.uuid as node_uuid,
    nodes.name as node_name,
    owners.uuid as owned_by_user_uuid
FROM new_peer_requests
    JOIN nodes on nodes.id = new_peer_requests.node_id
    JOIN users AS owners on owners.id = new_peer_requests.owned_by_user_id
WHERE
    new_peer_requests.random_id = COALESCE(sqlc.narg(random_id), new_peer_requests.random_id) AND
    (@include_completed OR new_peer_requests.status NOT IN ('created', 'cancelled'))
ORDER BY requested_at DESC;

-- name: UpdateNewPeerRequest :execrows
UPDATE new_peer_requests SET
    interface_name = @interface_name,
    requested_at = @requested_at,
    requested_by_user_uuid = @requested_by_user_uuid,
    status = @status
WHERE
    random_id = @random_id;

-- name: CancelNewPeerRequest :one
UPDATE new_peer_requests SET
    status = 'cancelled'
WHERE
    random_id = @random_id
RETURNING *;

--- ======= Request encryption keys ======= 

-- name: GetRequestEncryptionKeys :one
SELECT * FROM request_encryption_keys LIMIT 1;

-- name: UpdateRequestEncryptionKeys :execrows
UPDATE request_encryption_keys SET
    key0 = @key0,
    key1 = @key1,
    rotate_after = @rotate_after;
