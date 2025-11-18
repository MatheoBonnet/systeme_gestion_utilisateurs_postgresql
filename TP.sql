
DROP TABLE IF EXISTS logs_connexion;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS utilisateur_roles;
DROP TABLE IF EXISTS logs_connexion;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS utilisateurs;


-- 1.2
CREATE TABLE utilisateurs (
    id serial PRIMARY KEY,
    email VARCHAR(100) UNIQUE  NOT NULL CHECK(email LIKE '%@%.%'),
    password_hash TEXT NOT NULL,
    nom VARCHAR(50),
    prenom VARCHAR(50),
    actif BOOLEAN DEFAULT true,
    date_creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    date_modification TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_utilisateurs_email ON utilisateurs(email);
CREATE INDEX idx_utilisateurs_actif ON utilisateurs(actif);

CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    nom VARCHAR(50) NOT NULL UNIQUE,
    description TEXT,
    date_creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE permissions (
    id SERIAL PRIMARY KEY,
    nom VARCHAR(50) NOT NULL UNIQUE,
    ressource TEXT NOT NULL,
    action TEXT NOT NULL,
    description TEXT
);


-- 1.3
CREATE TABLE utilisateur_roles (
    utilisateur_id INT NOT NULL,
    role_id INT NOT NULL,
    date_assignation TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (utilisateur_id,role_id),
    FOREIGN KEY (utilisateur_id) REFERENCES utilisateurs(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

CREATE TABLE role_permissions (
    role_id INT ,
    permission_id INT ,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);

-- 1.4
CREATE TABLE sessions (
    id SERIAL PRIMARY KEY,
    utilisateur_id  INT NOT NULL,
    token TEXT NOT NULL,
    date_creation TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    date_expiration TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    actif BOOLEAN
);

CREATE TABLE logs_connexion (
    id SERIAL PRIMARY KEY,
    utilisateur_id INT,
    email_tentative VARCHAR(100) UNIQUE  NOT NULL CHECK(email_tentative LIKE '%@%.%'),
    date_heure TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    adresse_ip VARCHAR(16) CHECK (adresse_ip LIKE '%.%.%.%'),
    user_agent TEXT,
    succes BOOLEAN NOT NULL,
    message TEXT
);

-- 1.5
-- Insérer des rôles
INSERT INTO roles (nom, description) VALUES
('admin', 'Administrateur avec tous les droits'),
('moderator', 'Modérateur de contenu'),
('user', 'Utilisateur standard');
-- Insérer des permissions
INSERT INTO permissions (nom, ressource, action, description) VALUES
('read_users', 'users', 'read', 'Lire les utilisateurs'),
('write_users', 'users', 'write', 'Créer/modifier des utilisateurs'),
('delete_users', 'users', 'delete', 'Supprimer des utilisateurs'),
('read_posts', 'posts', 'read', 'Lire les posts'),
('write_posts', 'posts', 'write', 'Créer/modifier des posts'),
('delete_posts', 'posts', 'delete', 'Supprimer des posts');


INSERT INTO role_permissions (role_id,permission_id) VALUES
((SELECT id FROM roles WHERE nom LIKE 'admin'),(SELECT id FROM permissions WHERE nom LIKE 'read_users')),
((SELECT id FROM roles WHERE nom LIKE 'admin'),(SELECT id FROM permissions WHERE nom LIKE 'write_users')),
((SELECT id FROM roles WHERE nom LIKE 'admin'),(SELECT id FROM permissions WHERE nom LIKE 'delete_users')),
((SELECT id FROM roles WHERE nom LIKE 'admin'),(SELECT id FROM permissions WHERE nom LIKE 'read_posts')),
((SELECT id FROM roles WHERE nom LIKE 'admin'),(SELECT id FROM permissions WHERE nom LIKE 'write_posts')),
((SELECT id FROM roles WHERE nom LIKE 'admin'),(SELECT id FROM permissions WHERE nom LIKE 'delete_posts')),
((SELECT id FROM roles WHERE nom LIKE 'moderator'),(SELECT id FROM permissions WHERE nom LIKE 'read_users')),
((SELECT id FROM roles WHERE nom LIKE 'moderator'),(SELECT id FROM permissions WHERE nom LIKE 'read_posts')),
((SELECT id FROM roles WHERE nom LIKE 'moderator'),(SELECT id FROM permissions WHERE nom LIKE 'write_posts')),
((SELECT id FROM roles WHERE nom LIKE 'moderator'),(SELECT id FROM permissions WHERE nom LIKE 'delete_posts')),
((SELECT id FROM roles WHERE nom LIKE 'user'),(SELECT id FROM permissions WHERE nom LIKE 'read_users')),
((SELECT id FROM roles WHERE nom LIKE 'user'),(SELECT id FROM permissions WHERE nom LIKE 'read_posts')),
((SELECT id FROM roles WHERE nom LIKE 'user'),(SELECT id FROM permissions WHERE nom LIKE 'write_posts'));

SELECT * FROM role_permissions;

-- 1.6 
CREATE OR REPLACE FUNCTION utilisateur_a_permission(
  p_utilisateur_id INT,
  p_ressource VARCHAR,
  p_action VARCHAR
)
RETURNS BOOLEAN AS $$
BEGIN
  -- Retourne TRUE si l'utilisateur est actif et possède via ses rôles
  -- une permission correspondant à (ressource, action)
  RETURN EXISTS (
    SELECT 1
    FROM utilisateurs u
    JOIN utilisateur_roles ur ON ur.utilisateur_id = u.id
    JOIN role_permissions rp ON rp.role_id = ur.role_id
    JOIN permissions p ON p.id = rp.permission_id
    WHERE u.id = p_utilisateur_id
      AND u.actif = TRUE
      AND p.ressource = p_ressource
      AND p.action = p_action
  );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

--Task 7
SELECT
  u.id,
  u.email,
  u.nom,
  u.prenom,
  u.actif,
  u.date_creation,
  array_remove(array_agg(r.nom), NULL) AS roles
FROM utilisateurs u
LEFT JOIN utilisateur_roles ur ON ur.utilisateur_id = u.id
LEFT JOIN roles r ON r.id = ur.role_id
WHERE u.id = 1
GROUP BY u.id;


-- Task 8 : récupérer toutes les permissions d'un utilisateur
SELECT DISTINCT
  u.id AS utilisateur_id,
  u.email,
  p.nom AS permission,
  p.ressource,
  p.action
FROM utilisateurs u
JOIN utilisateur_roles ur ON ur.utilisateur_id = u.id
JOIN roles r ON r.id = ur.role_id
JOIN role_permissions rp ON rp.role_id = r.id
JOIN permissions p ON p.id = rp.permission_id
WHERE u.id = 1
ORDER BY p.ressource, p.action;

-- Task 9 : compter le nombre d'utilisateurs par rôle
SELECT
  r.nom AS role,
  COUNT(ur.utilisateur_id) AS nombre_utilisateurs
FROM roles r
LEFT JOIN utilisateur_roles ur ON ur.role_id = r.id
GROUP BY r.nom
ORDER BY nombre_utilisateurs DESC;

-- Task 10 : utilisateurs ayant à la fois 'admin' ET 'moderator'
SELECT
  u.id,
  u.email,
  array_agg(DISTINCT r.nom) AS roles
FROM utilisateurs u
JOIN utilisateur_roles ur ON ur.utilisateur_id = u.id
JOIN roles r ON r.id = ur.role_id
WHERE r.nom IN ('admin', 'moderator')
GROUP BY u.id, u.email
HAVING COUNT(DISTINCT r.nom) = 2;

-- Task 11 : (déjà fourni dans l'énoncé) tentatives échouées des 7 derniers jours
SELECT
    DATE(date_heure) AS jour,
    COUNT(*) AS tentatives_echouees
FROM logs_connexion
WHERE succes = FALSE
  AND date_heure >= CURRENT_DATE - INTERVAL '7 days'
GROUP BY DATE(date_heure)
ORDER BY jour DESC;

CREATE OR REPLACE FUNCTION est_token_valide(p_token VARCHAR)
RETURNS BOOLEAN AS $$
BEGIN
RETURN EXISTS (
SELECT 1
FROM sessions s
INNER JOIN utilisateurs u ON s.utilisateur_id = u.id
WHERE s.token = p_token
AND s.actif = true
AND s.date_expiration > CURRENT_TIMESTAMP
AND u.actif = true
);
END;
$$ LANGUAGE plpgsql;



