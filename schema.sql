
CREATE TABLE user(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name VARCHAR(255) NOT NULL UNIQUE,
  password TEXT,
  expires TEXT, -- datetime
  greeting TEXT,
  max_ttl TEXT DEFAULT "30d", -- golang auth.Duration
  second_factor BOOLEAN DEFAULT 1,
  schedule TEXT -- golang auth.Schedule
);

CREATE INDEX user_id ON user(id);
CREATE INDEX user_name ON user(name);

CREATE TABLE credential(
    user INTEGER NOT NULL,
    data text NOT NULL,
    FOREIGN KEY(user) REFERENCES user(id) ON DELETE CASCADE
);

CREATE INDEX credential_user ON credential(id);


CREATE TABLE session(
  token TEXT PRIMARY KEY,
  user INTEGER NOT NULL,
  expires TEXT NOT NULL, -- datetime
  FOREIGN KEY(user) REFERENCES user(id) ON DELETE CASCADE
);

CREATE INDEX session_token ON session(token);


CREATE TABLE sessions (
	token TEXT PRIMARY KEY,
	data BLOB NOT NULL,
	expiry REAL NOT NULL
);

CREATE INDEX sessions_expiry_idx ON sessions(expiry);