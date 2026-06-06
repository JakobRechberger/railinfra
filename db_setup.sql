-- RailInfra CTF — Database setup
-- Run once during Ansible provisioning via the mysql role.
-- Two separate tables with a deliberate design split:
--
--   `users`    — injectable, dummy data only (SQL injection rabbit hole)
--   `accounts` — real credentials, parameterised queries only (not injectable)
--
-- The attacker finds the injectable `users` table via sqlmap but gets nothing
-- useful from it. The real operator/supervisor credentials are in `accounts`
-- and are only reachable via the debug bypass or normal parameterised login.

CREATE DATABASE IF NOT EXISTS railinfra
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE railinfra;

-- -------------------------------------------------------------------------
-- Table: users
-- SQL injection rabbit hole. The login form queries this table with an
-- unsanitised f-string (see app.py Path B). sqlmap will detect and dump it.
-- All password hashes are placeholder MD5s that do not correspond to any
-- real account — the attacker wastes time here before pivoting to ?debug=true.
-- -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  username      VARCHAR(50)  NOT NULL,
  password      VARCHAR(100) NOT NULL,
  password_hash VARCHAR(100) NOT NULL,
  role          VARCHAR(20)  NOT NULL DEFAULT 'operator',
  created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- Dummy rows — realistic-looking but no working credentials
INSERT INTO users (username, password, password_hash, role) VALUES
  ('admin',    'placeholder', '5f4dcc3b5aa765d61d8327deb882cf99', 'admin'),
  ('operator', 'placeholder', 'e10adc3949ba59abbe56e057f20f883e', 'operator'),
  ('backup',   'placeholder', 'd8578edf8458ce06fbc5bb76a58c5ca4', 'operator'),
  ('testuser', 'placeholder', '098f6bcd4621d373cade4e832627b4f6', 'operator');

-- -------------------------------------------------------------------------
-- Table: accounts
-- Real account table — queried with parameterised statements only (not
-- injectable). Passwords stored as plaintext for CTF simplicity; Ansible
-- sets operator_password = Rail2026! (same as defaults.conf default_password)
-- so the IVR → SSH → webapp credential chain is consistent.
-- -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS accounts (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  username      VARCHAR(50)  NOT NULL UNIQUE,
  password_hash VARCHAR(100) NOT NULL,   -- plaintext here; label kept for schema realism
  role          VARCHAR(20)  NOT NULL DEFAULT 'operator'
) ENGINE=InnoDB;

-- Passwords are inserted by Ansible using the extra_vars values, not here.
-- The INSERT below uses placeholder values that Ansible overwrites via
-- the mysql_query task with the real provisioned passwords.
-- If running manually for local dev, replace the password values:
INSERT INTO accounts (username, password_hash, role) VALUES
  ('operator',   'Rail2026!',    'operator'),
  ('supervisor', 'supervisor123','supervisor')
ON DUPLICATE KEY UPDATE
  password_hash = VALUES(password_hash),
  role          = VALUES(role);

-- -------------------------------------------------------------------------
-- Table: signal_events (optional — for future DB-backed signal log)
-- Not used in v1 (SIGNAL_LOGS is hardcoded in app.py) but present for
-- realism; attackers enumerating the DB will find it.
-- -------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS signal_events (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  signal_id  VARCHAR(20) NOT NULL,
  location   VARCHAR(100),
  severity   ENUM('INFO','WARN','ERROR') NOT NULL DEFAULT 'INFO',
  content    TEXT,
  raw        VARCHAR(200),
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- Seed a few rows so the table looks live
INSERT INTO signal_events (signal_id, location, severity, content, raw) VALUES
  ('SIG-A', 'Main line entry',    'INFO',  'State change: HALT → GO',          'SIGSTATE SIG-A 0x01'),
  ('SIG-D', 'Factory B approach', 'WARN',  'State change: GO → HALT',           'SIGSTATE SIG-D 0x00'),
  ('SW-4',  'Factory siding B',   'INFO',  'Switch position: NORMAL → DIVERGE', 'SWPOS SW-4 0x02');
