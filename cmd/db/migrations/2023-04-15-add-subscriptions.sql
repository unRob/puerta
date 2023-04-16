CREATE TABLE subscription(
  user INTEGER NOT NULL,
  data TEXT NOT NULL,
  FOREIGN KEY(user) REFERENCES user(id) ON DELETE CASCADE
);

CREATE INDEX subscription_user ON subscription(user);

ALTER TABLE user ADD COLUMN receives_notifications BOOLEAN DEFAULT 0 NOT NULL;


