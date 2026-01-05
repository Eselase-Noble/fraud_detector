CREATE TABLE transactions (
    transaction_id VARCHAR PRIMARY KEY,
    user_id VARCHAR NOT NULL,
    amount NUMERIC NOT NULL,
    currency VARCHAR(3),
    merchant VARCHAR,
    location VARCHAR,
    timestamp TIMESTAMP NOT NULL
);
