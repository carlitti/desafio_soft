const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const morgan = require('morgan');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
require('dotenv').config();


app.use(bodyParser.json());
app.use(morgan('dev'));


const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgres://user:password@localhost/softjobs'
});

app.listen(3000, () => console.log('Servidor corriendo en el puerto 3000'));

app.post('/usuarios', async (req, res) => {
    const { email, password, rol, lenguage } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO usuarios (email, password, rol, lenguage) VALUES ($1, $2, $3, $4) RETURNING *',
            [email, hashedPassword, rol, lenguage]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: 'Error al registrar el usuario' });
    }
});

app.post('/usuarios', async (req, res) => {
    const { email, password, rol, lenguage } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO usuarios (email, password, rol, lenguage) VALUES ($1, $2, $3, $4) RETURNING *',
            [email, hashedPassword, rol, lenguage]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: 'Error al registrar el usuario' });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
        if (user.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

        const validPassword = await bcrypt.compare(password, user.rows[0].password);
        if (!validPassword) return res.status(401).json({ error: 'Contraseña incorrecta' });

        const token = jwt.sign({ email }, process.env.JWT_SECRET || 'secretkey');
        res.status(200).json({ token });
    } catch (err) {
        res.status(500).json({ error: 'Error al iniciar sesión' });
    }
});

app.get('/usuarios', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token no proporcionado' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secretkey');
        const user = await pool.query('SELECT * FROM usuarios WHERE email = $1', [decoded.email]);
        if (user.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

        res.status(200).json(user.rows[0]);
    } catch (err) {
        res.status(401).json({ error: 'Token inválido' });
    }
});
