const { Pool } = require('pg');
require('dotenv').config();
const pool = new Pool({
	// Configuration de connexion lue depuis les variables d'environnement
	user: process.env.DB_USER || process.env.PGUSER,
	host: process.env.DB_HOST || process.env.PGHOST,
	database: process.env.DB_NAME || process.env.PGDATABASE,
	password: process.env.DB_PASSWORD || process.env.PGPASSWORD,
	port: parseInt(process.env.DB_PORT || process.env.PGPORT, 10) || 5432,
});
pool.on('connect', () => {
console.log('✅ Connecté à PostgreSQL');
});
pool.on('error', (err) => {
console.error('❌ Erreur PostgreSQL:', err);
});
module.exports = pool;