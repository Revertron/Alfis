CREATE TABLE blocks (
    'id' BIGINT NOT NULL PRIMARY KEY,
    'timestamp' BIGINT NOT NULL,
    'version' INT,
    'difficulty' INTEGER,
    'random' INTEGER,
    'nonce' INTEGER,
    'transaction' TEXT,
    'prev_block_hash' BINARY,
    'hash' BINARY,
    'pub_key' BINARY,
    'signature' BINARY
);
CREATE INDEX block_index ON blocks (id);
CREATE INDEX keys ON blocks (pub_key);

CREATE TABLE domains (
    'id' BIGINT NOT NULL PRIMARY KEY,
    'timestamp' BIGINT NOT NULL,
    'identity' BINARY,
    'confirmation' BINARY,
    'data' TEXT,
    'pub_key' BINARY
);
CREATE INDEX ids ON domains ('identity');

CREATE TABLE zones (
    'id' BIGINT NOT NULL PRIMARY KEY,
    'timestamp' BIGINT NOT NULL,
    'identity' BINARY,
    'confirmation' BINARY,
    'data' TEXT,
    'pub_key' BINARY
);

CREATE TABLE options ('name' TEXT NOT NULL, 'value' TEXT NOT NULL);