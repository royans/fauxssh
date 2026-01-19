CREATE DATABASE IF NOT EXISTS finance_db;
USE finance_db;

CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY,
    username VARCHAR(50),
    password_hash VARCHAR(64),
    role VARCHAR(20)
);

CREATE TABLE IF NOT EXISTS transactions (
    id INT PRIMARY KEY,
    amount DECIMAL(10,2),
    description TEXT,
    created_at DATETIME
);
