const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');
const mysql = require('mysql2');

const app = express();

// Secret pour le JWT
const JWT_SECRET = 'ton_secret_super_securise'; // Remplace par une valeur complexe en production.

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root', // Ton utilisateur MySQL
    password: '', // Ton mot de passe MySQL
    database: 'task_manager'
});

db.connect((err) => {
    if (err) throw err;
    console.log('MySQL Connected...');
});

// Middleware
app.use(bodyParser.json());
app.use(cors());

// Inscription (Signup)
app.post(
  '/signup',
  [
    check('email', 'Email invalide').isEmail(),
    check('password', 'Le mot de passe doit contenir au moins 6 caractères').isLength({ min: 6 }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    // Vérifie si l'utilisateur existe déjà
    const sqlCheck = 'SELECT * FROM users WHERE email = ?';
    db.query(sqlCheck, [email], async (err, results) => {
      if (err) throw err;

      if (results.length > 0) {
        return res.status(400).json({ message: 'Email déjà utilisé' });
      }

      // Hacher le mot de passe
      const hashedPassword = await bcrypt.hash(password, 10);

      const sqlInsert = 'INSERT INTO users (email, password) VALUES (?, ?)';
      db.query(sqlInsert, [email, hashedPassword], (err) => {
        if (err) throw err;
        res.json({ message: 'Utilisateur créé avec succès' });
      });
    });
  }
);

// Connexion (Login)
app.post(
  '/login',
  [
    check('email', 'Email invalide').isEmail(),
    check('password', 'Le mot de passe est obligatoire').exists(),
  ],
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    // Vérifie si l'utilisateur existe dans la base de données
    const sql = 'SELECT * FROM users WHERE email = ?';
    db.query(sql, [email], async (err, results) => {
      if (err) throw err;

      if (results.length === 0) {
        return res.status(400).json({ message: 'Email ou mot de passe incorrect' });
      }

      const user = results[0];

      // Vérifie si le mot de passe correspond
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ message: 'Email ou mot de passe incorrect' });
      }

      // Génère un token JWT
      const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1h' });

      res.json({ message: 'Connexion réussie', token });
    });
  }
);

// Middleware pour protéger les routes avec un token
function authenticateToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ message: 'Token manquant' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Token invalide' });
    req.user = user;
    next();
  });
}

// Exemple : Route protégée
app.get('/profile', authenticateToken, (req, res) => {
  res.json({ message: `Bienvenue, utilisateur ID : ${req.user.id}` });
});

app.get('/tasks', authenticateToken, (req, res) => {
  const sql = 'SELECT * FROM tasks WHERE user_id = ?';
  db.query(sql, [req.user.id], (err, results) => {
      if (err) throw err;
      res.json(results);
  });
});


app.post('/tasks', authenticateToken, (req, res) => {
  const { title, description, priority, statut } = req.body; // Assurez-vous que 'statut' est reçu ici
  const sql =
    'INSERT INTO tasks (title, description, priority, status, user_id) VALUES (?, ?, ?, ?, ?)';
  db.query(
    sql,
    [title, description, priority, statut, req.user.id],
    (err, result) => {
      if (err) throw err;
      res.json({ message: 'Task created', id: result.insertId });
    }
  );
});



// Mettre à jour une tâche (uniquement par son propriétaire)
app.put('/tasks/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { title, description, priority, status } = req.body;

  const sql =
    'UPDATE tasks SET title = ?, description = ?, priority = ?, status = ? WHERE id = ? AND user_id = ?';
  db.query(
    sql,
    [title, description, priority, status, id, req.user.id],
    (err) => {
      if (err) throw err;
      res.json({ message: 'Tâche mise à jour' });
    }
  );
});

// Supprimer une tâche (uniquement par son propriétaire)
app.delete('/tasks/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const sql = 'DELETE FROM tasks WHERE id = ? AND user_id = ?';
  db.query(sql, [id, req.user.id], (err) => {
      if (err) throw err;
      res.json({ message: 'Task deleted' });
  });
});
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
