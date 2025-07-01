CREATE TABLE IF NOT EXISTS sessions
(
    id            SERIAL PRIMARY KEY,
    user_id       uuid NOT NULL,
    refresh_token TEXT NOT NULL,
    user_agent    TEXT NOT NULL,
    ip            TEXT NOT NULL,
    expires_at    TIMESTAMP NOT NULL,
    created_at    TIMESTAMP NOT NULL DEFAULT NOW()
);
