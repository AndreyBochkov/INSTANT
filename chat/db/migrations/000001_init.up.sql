CREATE SCHEMA IF NOT EXISTS chat_schema;
CREATE TABLE IF NOT EXISTS chat_schema.chats
(
    chatid SERIAL PRIMARY KEY,
    user1 INT NOT NULL,
    user2 INT NOT NULL,
    label1 TEXT NOT NULL,
    label2 TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS chat_schema.messages
(
    messageid BIGSERIAL PRIMARY KEY,
    chatid INT NOT NULL,
    ts BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())),
    body TEXT NOT NULL,
    sender INT NOT NULL
);
CREATE TABLE IF NOT EXISTS chat_schema.sync
(
    id INT UNIQUE NOT NULL,
    body TEXT NOT NOT,
    sessionkey BYTEA NOT NULL
);
CREATE TABLE IF NOT EXISTS chat_schema.syncable
(
    id INT UNIQUE NOT NULL,
    sessionkey BYTEA NOT NULL
);