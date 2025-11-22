const Database = require("better-sqlite3")

const db = new Database("database.db")

db.pragma('foreign_keys = ON');

db.exec(
    `
    CREATE TABLE IF NOT EXISTS Users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    `
)

db.exec(
    `
    CREATE TABLE IF NOT EXISTS Books (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        year INTEGER NOT NULL,
        genre TEXT NOT NULL,
        description TEXT NOT NULL,
        createdBy INTEGER NOT NULL,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (createdBy) REFERENCES Users(id) ON DELETE CASCADE
    )
    `
)

db.exec(
    `
    CREATE TABLE IF NOT EXISTS Reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bookId INTEGER NOT NULL,
        userId INTEGER NOT NULL,
        rating INTEGER NOT NULL,
        comment TEXT NOT NULL,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (bookId) REFERENCES Books(id) ON DELETE CASCADE,
        FOREIGN KEY (userId) REFERENCES Users(id) ON DELETE CASCADE
    )
    `
)

module.exports = db