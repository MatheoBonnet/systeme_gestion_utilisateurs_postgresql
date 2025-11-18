const express = require('express');
const pool = require('./database/db');
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const app = express();
const PORT = process.env.PORT || 3000;
// Middleware
app.use(express.json());
// Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
// Health check
app.get('/api/health', async (req, res) => {
	try {
		const result = await pool.query('SELECT NOW()');
		return res.json({ ok: true, now: result.rows[0].now });
	} catch (err) {
		console.error('error db', err);
		return res.status(500).json({ ok: false, error: 'Database connection error' });
	}
});
app.listen(PORT, () => {
console.log(`🚀 Serveur démarré sur http://localhost:${PORT}`);
});