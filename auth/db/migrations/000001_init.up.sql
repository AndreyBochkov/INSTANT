CREATE SCHEMA IF NOT EXISTS auth_schema;
CREATE TABLE IF NOT EXISTS auth_schema.users
(
    id SERIAL PRIMARY KEY,
    login TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name VARCHAR(100)
);