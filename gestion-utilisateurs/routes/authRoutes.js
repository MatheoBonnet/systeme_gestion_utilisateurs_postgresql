const express = require('express');
const router = express.Router();
const pool = require('../database/db');
const { requireAuth } = require('../middleware/auth');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
// Route de connexion
router.post('/login', async (req, res) => {
	const { email, password } = req.body;
	const client = await pool.connect();
	try {
		await client.query('BEGIN');
		// 1. Récupérer l'utilisateur par email (inclure password_hash et actif)
		const userResult = await client.query(
			'SELECT id, email, password_hash, nom, prenom, actif FROM utilisateurs WHERE email = $1',
			[email]
		);
		if (userResult.rows.length === 0) {
			// Logger l'échec (email inconnu)
			await client.query(
				`INSERT INTO logs_connexion (utilisateur_id, email_tentative, adresse_ip, user_agent, succes, message)
				 VALUES ($1,$2,$3,$4,$5,$6)
				 ON CONFLICT (email_tentative) DO UPDATE
				 SET date_heure = EXCLUDED.date_heure, adresse_ip = EXCLUDED.adresse_ip,
				     user_agent = EXCLUDED.user_agent, succes = EXCLUDED.succes, message = EXCLUDED.message`,
				[null, email, req.ip || null, req.headers['user-agent'] || null, false, 'Email inconnu']
			);
			await client.query('COMMIT');
			return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
		}
		const user = userResult.rows[0];
		// 2. Vérifier si l'utilisateur est actif
		if (!user.actif) {
			// Logger l'échec (compte inactif)
			await client.query(
				`INSERT INTO logs_connexion (utilisateur_id, email_tentative, adresse_ip, user_agent, succes, message)
				 VALUES ($1,$2,$3,$4,$5,$6)
				 ON CONFLICT (email_tentative) DO UPDATE
				 SET date_heure = EXCLUDED.date_heure, adresse_ip = EXCLUDED.adresse_ip,
				     user_agent = EXCLUDED.user_agent, succes = EXCLUDED.succes, message = EXCLUDED.message`,
				[user.id, email, req.ip || null, req.headers['user-agent'] || null, false, 'Compte inactif']
			);
			await client.query('COMMIT');
			return res.status(403).json({ error: 'Compte inactif' });
		}
		// 3. Comparer le mot de passe
		const passwordMatch = await bcrypt.compare(password, user.password_hash);
		if (!passwordMatch) {
			// Logger l'échec (mauvais mot de passe)
			await client.query(
				`INSERT INTO logs_connexion (utilisateur_id, email_tentative, adresse_ip, user_agent, succes, message)
				 VALUES ($1,$2,$3,$4,$5,$6)
				 ON CONFLICT (email_tentative) DO UPDATE
				 SET date_heure = EXCLUDED.date_heure, adresse_ip = EXCLUDED.adresse_ip,
				     user_agent = EXCLUDED.user_agent, succes = EXCLUDED.succes, message = EXCLUDED.message`,
				[user.id, email, req.ip || null, req.headers['user-agent'] || null, false, 'Mot de passe incorrect']
			);
			await client.query('COMMIT');
			return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
		}
		// 4. Générer token (UUID v4)
		const token = uuidv4();
		const expiresAt = new Date();
		expiresAt.setHours(expiresAt.getHours() + 24);
		// 5. Créer une session (expiration 24h)
		await client.query(
			`INSERT INTO sessions (utilisateur_id, token, date_expiration, actif)
			 VALUES ($1, $2, $3, $4)`,
			[user.id, token, expiresAt, true]
		);
		// 6. Logger succès
		await client.query(
			`INSERT INTO logs_connexion (utilisateur_id, email_tentative, adresse_ip, user_agent, succes, message)
			 VALUES ($1,$2,$3,$4,$5,$6)
			 ON CONFLICT (email_tentative) DO UPDATE
			 SET date_heure = EXCLUDED.date_heure, adresse_ip = EXCLUDED.adresse_ip,
			     user_agent = EXCLUDED.user_agent, succes = EXCLUDED.succes, message = EXCLUDED.message`,
			[user.id, email, req.ip || null, req.headers['user-agent'] || null, true, 'Connexion réussie']
		);
		await client.query('COMMIT');
		// Retourner token et infos utilisateur (sans password)
		res.json({
			message: 'Connexion réussie',
			token: token,
			user: {
				id: user.id,
				email: user.email,
				nom: user.nom,
				prenom: user.prenom
			},
			expiresAt: expiresAt
		});
	} catch (error) {
		await client.query('ROLLBACK');
		console.error('Erreur login:', error);
		res.status(500).json({ error: 'Erreur serveur' });
	} finally {
		client.release();
	}
});
router.post('/register', async (req, res) => {
const { email, password, nom, prenom } = req.body;
// 1. Validation
if (!email || !password) {
	return res.status(400).json({ error: 'Email et mot de passe requis' });
}
const client = await pool.connect();
try {
await client.query('BEGIN');
// 2. Vérifier si email existe
const checkUser = await client.query(
	'SELECT id FROM utilisateurs WHERE email = $1',
	[email]
);
if (checkUser.rows.length > 0) {
	await client.query('ROLLBACK');
	return res.status(409).json({ error: 'Email déjà enregistré' });
}
// 3. Hasher le mot de passe
const passwordHash = await bcrypt.hash(password, 10);
// 4. Insérer l'utilisateur
const result = await client.query(
	`INSERT INTO utilisateurs (email, password_hash, nom, prenom)
	 VALUES ($1, $2, $3, $4)
	 RETURNING id, email, nom, prenom, date_creation`,
	[email, passwordHash, nom || null, prenom || null]
);const newUser = result.rows[0];
// 5. Assigner le rôle "user"
await client.query(
	`INSERT INTO utilisateur_roles (utilisateur_id, role_id)
	 VALUES ($1, (SELECT id FROM roles WHERE nom = 'user'))`,
	[newUser.id]
);
await client.query('COMMIT');
res.status(201).json({
message: 'Utilisateur créé avec succès',
user: newUser
});
} catch (error) {
await client.query('ROLLBACK');
console.error('Erreur création utilisateur:', error);
res.status(500).json({ error: 'Erreur serveur' });
} finally {
client.release();
}
});
module.exports = router;

// GET /api/auth/profile
router.get('/profile', requireAuth, async (req, res) => {
	try {
		// Récupérer l'utilisateur avec ses rôles
		const result = await pool.query(
			`SELECT u.id, u.email, u.nom, u.prenom, u.actif, u.date_creation,
							array_remove(array_agg(r.nom), NULL) AS roles
			 FROM utilisateurs u
			 LEFT JOIN utilisateur_roles ur ON ur.utilisateur_id = u.id
			 LEFT JOIN roles r ON r.id = ur.role_id
			 WHERE u.id = $1
			 GROUP BY u.id, u.email, u.nom, u.prenom, u.actif, u.date_creation`,
			[req.user.id]
		);
		res.json({ user: result.rows[0] });
	} catch (error) {
		console.error('Erreur profil:', error);
		res.status(500).json({ error: 'Erreur serveur' });
	}
});

// POST /api/auth/logout
router.post('/logout', requireAuth, async (req, res) => {
	const authHeader = req.headers['authorization'] || '';
	const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
	try {
		// 1. Désactiver la session
		const updateRes = await pool.query(
			`UPDATE sessions SET actif = FALSE WHERE token = $1 RETURNING utilisateur_id`,
			[token]
		);

		if (updateRes.rows.length === 0) {
			return res.status(400).json({ error: 'Session non trouvée' });
		}

		const utilisateurId = updateRes.rows[0].utilisateur_id;

		// 2. Logger la déconnexion dans logs_connexion
		await pool.query(
			`INSERT INTO logs_connexion (utilisateur_id, email_tentative, adresse_ip, user_agent, succes, message)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			[utilisateurId, req.user && req.user.email ? req.user.email : null, req.ip || null, req.headers['user-agent'] || null, true, 'Déconnexion']
		);

		res.json({ message: 'Déconnecté avec succès' });
	} catch (error) {
		console.error('Erreur logout:', error);
		res.status(500).json({ error: 'Erreur serveur' });
	}
});

// GET /api/auth/logs
router.get('/logs', requireAuth, async (req, res) => {
	try {
		const utilisateurId = req.user.utilisateur_id || req.user.id;
		const result = await pool.query(
			`SELECT * FROM logs_connexion
			 WHERE utilisateur_id = $1
			 ORDER BY date_heure DESC
			 LIMIT 50`,
			[utilisateurId]
		);
		res.json({ logs: result.rows });
	} catch (error) {
		console.error('Erreur logs:', error);
		res.status(500).json({ error: 'Erreur serveur' });
	}
});