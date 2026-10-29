const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const logger = require('./logger');

const pool = new Pool({
  host: process.env.PGHOST || 'localhost',
  port: Number(process.env.PGPORT) || 5432,
  user: process.env.PGUSER || 'notes',
  password: process.env.PGPASSWORD || 'notes',
  database: process.env.PGDATABASE || 'notes',
});

async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(20) NOT NULL DEFAULT 'user' CHECK (role IN ('user','moderator','admin')),
      failed_attempts INT NOT NULL DEFAULT 0,
      locked_until TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      id SERIAL PRIMARY KEY,
      user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL,
      user_agent TEXT,
      ip TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL,
      revoked BOOLEAN NOT NULL DEFAULT FALSE
    );
    CREATE INDEX IF NOT EXISTS sessions_token_hash_idx ON sessions(token_hash);
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS notes (
      id SERIAL PRIMARY KEY,
      user_id INT REFERENCES users(id) ON DELETE CASCADE,
      title VARCHAR(200) NOT NULL,
      content TEXT NOT NULL,
      image_url TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  await pool.query(`ALTER TABLE notes ADD COLUMN IF NOT EXISTS user_id INT REFERENCES users(id) ON DELETE CASCADE;`);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS password_resets (
      id SERIAL PRIMARY KEY,
      user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used BOOLEAN NOT NULL DEFAULT FALSE
    );
  `);

  const adminEmail = (process.env.ADMIN_EMAIL || 'admin@example.com').toLowerCase();
  const adminPassword = process.env.ADMIN_PASSWORD || 'Admin123!';
  if (!(await pool.query('SELECT id FROM users WHERE email=$1', [adminEmail])).rows[0]) {
    await pool.query('INSERT INTO users (email, password_hash, role) VALUES ($1,$2,$3)',
      [adminEmail, await bcrypt.hash(adminPassword, 10), 'admin']);
    logger.info({ email: adminEmail }, 'seed: admin created');
  }

  const modEmail = (process.env.MODERATOR_EMAIL || 'moderator@example.com').toLowerCase();
  const modPassword = process.env.MODERATOR_PASSWORD || 'Moder123!';
  if (!(await pool.query('SELECT id FROM users WHERE email=$1', [modEmail])).rows[0]) {
    await pool.query('INSERT INTO users (email, password_hash, role) VALUES ($1,$2,$3)',
      [modEmail, await bcrypt.hash(modPassword, 10), 'moderator']);
    logger.info({ email: modEmail }, 'seed: moderator created');
  }

  await pool.query(`UPDATE notes SET user_id = (SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1) WHERE user_id IS NULL`);
}

module.exports = { pool, init };