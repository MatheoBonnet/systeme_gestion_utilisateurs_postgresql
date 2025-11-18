const express = require('express');
const router = express.Router();
const pool = require('../database/db');
const { requireAuth, requirePermission } = require('../middleware/auth');

// GET /api/users?page=1&limit=10
router.get('/',
  requireAuth,
  requirePermission('users', 'read'),
  async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;
    try {
      // 1. Compter le total d'utilisateurs
      const countRes = await pool.query('SELECT COUNT(*)::int AS total FROM utilisateurs');
      const total = countRes.rows[0].total;

      // 2. Récupérer les utilisateurs avec leurs rôles (array_agg)
      // 3. Utiliser LIMIT et OFFSET pour la pagination
      const usersRes = await pool.query(
        `SELECT u.id, u.email, u.nom, u.prenom, u.actif, u.date_creation,
                array_remove(array_agg(r.nom), NULL) AS roles
         FROM utilisateurs u
         LEFT JOIN utilisateur_roles ur ON ur.utilisateur_id = u.id
         LEFT JOIN roles r ON r.id = ur.role_id
         GROUP BY u.id, u.email, u.nom, u.prenom, u.actif, u.date_creation
         ORDER BY u.id
         LIMIT $1 OFFSET $2`,
        [limit, offset]
      );

      // 4. Retourner users et pagination info
      const totalPages = Math.ceil(total / limit);
      res.json({
        users: usersRes.rows,
        pagination: {
          page,
          limit,
          total,
          totalPages
        }
      });
    } catch (error) {
      console.error('Erreur liste utilisateurs:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// DELETE /api/users/:id
router.delete('/:id',
  requireAuth,
  requirePermission('users', 'delete'),
  async (req, res) => {
    const { id } = req.params;
    // Empêcher l'auto-suppression
    if (parseInt(id) === req.user.utilisateur_id) {
      return res.status(400).json({
        error: 'Vous ne pouvez pas supprimer votre propre compte'
      });
    }
    try {
      const result = await pool.query(
        `DELETE FROM utilisateurs WHERE id = $1 RETURNING id, email, nom, prenom, actif, date_creation`,
        [id]
      );
      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Utilisateur non trouvé' });
      }
      res.json({
        message: 'Utilisateur supprimé',
        user: result.rows[0]
      });
    } catch (error) {
      console.error('Erreur suppression utilisateur:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

module.exports = router;

// GET /api/users/:id/permissions
router.get('/:id/permissions',
  requireAuth,
  requirePermission('users', 'read'),
  async (req, res) => {
    const { id } = req.params;
    try {
      // Récupérer toutes les permissions associées aux rôles de l'utilisateur
      const result = await pool.query(
        `SELECT DISTINCT p.nom, p.ressource, p.action, p.description
         FROM utilisateurs u
         INNER JOIN utilisateur_roles ur ON u.id = ur.utilisateur_id
         INNER JOIN roles r ON r.id = ur.role_id
         INNER JOIN role_permissions rp ON rp.role_id = r.id
         INNER JOIN permissions p ON p.id = rp.permission_id
         WHERE u.id = $1
         ORDER BY p.ressource, p.action`,
        [id]
      );

      res.json({ permissions: result.rows });
    } catch (error) {
      console.error('Erreur récupération permissions utilisateur:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);

// PUT /api/users/:id
router.put('/:id',
  requireAuth,
  requirePermission('users', 'write'),
  async (req, res) => {
    const { id } = req.params;
    const { nom, prenom, actif } = req.body;
    try {
      const result = await pool.query(
        `UPDATE utilisateurs
         SET nom = $1, prenom = $2, actif = $3, date_modification = CURRENT_TIMESTAMP
         WHERE id = $4
         RETURNING id, email, nom, prenom, actif, date_modification`,
        [nom || null, prenom || null, actif, id]
      );
      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Utilisateur non trouvé' });
      }
      res.json({
        message: 'Utilisateur mis à jour',
        user: result.rows[0]
      });
    } catch (error) {
      console.error('Erreur mise à jour utilisateur:', error);
      res.status(500).json({ error: 'Erreur serveur' });
    }
  }
);
