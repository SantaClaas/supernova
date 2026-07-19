BEGIN;

-- CREATE TABLE IF NOT EXISTS projects (
--     id TEXT PRIMARY KEY,
--     name TEXT NOT NULL,
--     image_name TEXT NOT NULL,
--     token_hash BLOB
-- );
CREATE TABLE IF NOT EXISTS tokens (
    container_id TEXT PRIMARY KEY,
    token_hash BLOB NOT NULL
);

END;
