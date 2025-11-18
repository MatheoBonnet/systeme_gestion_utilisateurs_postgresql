const pool = require('../database/db');

async function requireAuth(req, res, next) {
    const token = req.headers['authorization'];

    if (!token) {
        // À COMPLÉTER
        return res.status(401).json({ error: 'Token manquant' });
    }

    try {
        // Vérifier que le token est valide
        const result = await pool.query(
            // À COMPLÉTER : requête JOIN sessions + utilisateurs
            `SELECT 
                s.utilisateur_id,
                u.email,
                u.nom,
                u.prenom,
                u.actif
            FROM sessions s
            INNER JOIN utilisateurs u ON s.utilisateur_id = u.id
            WHERE s.token = $1
              AND s.actif = TRUE
              AND s.date_expiration > NOW()
              AND u.actif = TRUE`,
            [token]
        );

        if (result.rows.length === 0) {
            // À COMPLÉTER
            return res.status(401).json({ error: 'Token invalide ou expiré' });
        }

        req.user = result.rows[0];
        next();

    } catch (error) {
        console.error('Erreur middleware auth:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
}

function requirePermission(ressource, action) {
    return async (req, res, next) => {
        try {
            const result = await pool.query(
                'SELECT utilisateur_a_permission($1, $2, $3) AS a_permission',
                [req.user.utilisateur_id, ressource, action]
            );

            if (!result.rows[0].a_permission) {
                return res.status(403).json({ error: 'Permission refusée' });
            }

            next();

        } catch (error) {
            console.error('Erreur vérification permission:', error);
            res.status(500).json({ error: 'Erreur serveur' });
        }
    };
}

// Alternative: utiliser la fonction stockée est_token_valide(p_token)
async function requireAuthWithFunction(req, res, next) {
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;

    if (!token) {
        return res.status(401).json({ error: 'Token manquant' });
    }

    try {
        // Utiliser la fonction stockée en base
        const validResult = await pool.query(
            'SELECT est_token_valide($1) AS valide',
            [token]
        );

        if (!validResult.rows[0] || !validResult.rows[0].valide) {
            return res.status(401).json({ error: 'Token invalide ou expiré' });
        }

        // Récupérer les infos utilisateur associées à la session
        const userResult = await pool.query(
            `SELECT s.utilisateur_id, u.email, u.nom, u.prenom
             FROM sessions s
             INNER JOIN utilisateurs u ON s.utilisateur_id = u.id
             WHERE s.token = $1`,
            [token]
        );

        if (!userResult.rows[0]) {
            return res.status(401).json({ error: 'Token invalide ou expiré' });
        }

        req.user = userResult.rows[0];
        next();
    } catch (error) {
        console.error('Erreur middleware auth (with function):', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
}

module.exports = { requireAuth, requirePermission, requireAuthWithFunction };
