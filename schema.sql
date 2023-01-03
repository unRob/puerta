
CREATE TABLE user(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  handle VARCHAR(255) NOT NULL UNIQUE,
  name TEXT NOT NULL,
  password TEXT,
  expires TEXT, -- datetime
  greeting TEXT,
  max_ttl TEXT DEFAULT "30d", -- golang auth.TTL
  schedule TEXT, -- golang auth.UserSchedule
  second_factor BOOLEAN DEFAULT 1,
  is_admin BOOLEAN DEFAULT 0 NOT NULL
);

CREATE INDEX user_id ON user(id);
CREATE INDEX user_handle ON user(handle);

CREATE TABLE credential(
  user INTEGER NOT NULL,
  data TEXT NOT NULL,
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

CREATE TABLE log(
  timestamp TEXT PRIMARY KEY,
  user TEXT NOT NULL,
  second_factor BOOLEAN NOT NULL,
  failure VARCHAR(255),
  error TEXT,
  ip_address varchar(255) NOT NULL,
  user_agent varchar(255) NOT NULL
);

CREATE INDEX log_timestamp_idx ON log(timestamp);
CREATE INDEX log_timestamp_error_idx ON log(timestamp,error);
CREATE INDEX log_timestamp_user_idx ON log(timestamp,user);
