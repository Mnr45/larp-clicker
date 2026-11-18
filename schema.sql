PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS accounts (
 id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE COLLATE NOCASE, name TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password_salt TEXT NOT NULL, password_hash TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS profiles (
 user_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE, name TEXT NOT NULL, save_json TEXT NOT NULL, updated_at INTEGER NOT NULL, last_chat INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS messages (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, message TEXT NOT NULL, created_at INTEGER NOT NULL, global_flag INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at DESC);
CREATE TABLE IF NOT EXISTS events (
 id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL, kind TEXT NOT NULL, starts_at INTEGER NOT NULL, ends_at INTEGER, created_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS gifts (
 id TEXT PRIMARY KEY, from_user_id TEXT NOT NULL, from_name TEXT NOT NULL, to_user_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, kind TEXT NOT NULL CHECK(kind IN ('gold','gems')), amount INTEGER NOT NULL CHECK(amount > 0), created_at INTEGER NOT NULL, claimed INTEGER NOT NULL DEFAULT 0, claimed_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_gifts_inbox ON gifts(to_user_id, claimed, created_at DESC);
