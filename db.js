const { Pool } = require('pg');

const isProduction = process.env.NODE_ENV === 'production' || process.env.VERCEL;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isProduction ? { rejectUnauthorized: false } : false
});

module.exports = pool;
