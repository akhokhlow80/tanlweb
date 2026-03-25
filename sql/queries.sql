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
