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
    ts TIMESTAMP WITHOUT TIME ZONE DEFAULT NOW(),
    body TEXT NOT NULL,
    sender INT NOT NULL
);