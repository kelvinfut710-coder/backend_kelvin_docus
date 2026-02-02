const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// --- 1. CONEXIÓN A BASE DE DATOS ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// --- 2. CONFIGURACIÓN DE CLOUDINARY ---
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// --- 3. CONFIGURACIÓN DE STORAGE ---
const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: async (req, file) => {
        const timestamp = Date.now();
        const cleanName = file.originalname.split('.')[0].replace(/\s+/g, '_').replace(/[^a-zA-Z0-9_]/g, '').toLowerCase();
        return {
            folder: 'sistema_vehicular',
            format: 'pdf',
            public_id: `${cleanName}_${timestamp}`
        };
    }
});

const upload = multer({ 
    storage: storage,
    fileFilter: (req, file, cb) => {
        if (file.mimetype === "application/pdf") {
            cb(null, true);
        } else {
            cb(new Error("SOLO_PDF_PERMITIDO"), false);
        }
    }
});

// --- 4. MIDDLEWARE DE SEGURIDAD ---
const verificarToken = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ error: 'Acceso denegado' });
    try {
        const verificado = jwt.verify(token.replace('Bearer ', ''), process.env.JWT_SECRET);
        req.user = verificado;
        next();
    } catch (err) {
        res.status(400).json({ error: 'Token no válido' });
    }
};

// --- 5. RUTAS DE USUARIO Y LOGIN ---
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE username = $1', [username]);
        if (result.rows.length === 0 || password !== result.rows[0].password_hash) {
            return res.status(400).json({ error: 'Credenciales incorrectas' });
        }
        const user = result.rows[0];
        const token = jwt.sign({ id: user.id, rol: user.rol }, process.env.JWT_SECRET, { expiresIn: '8h' });
        res.json({ token, rol: user.rol, nombre: user.nombre_completo });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/subir', verificarToken, upload.single('archivo'), async (req, res) => {
    const { tipo_documento, nombre_user } = req.body; 
    const usuario_id = req.user.id;
    try {
        await pool.query(
            'INSERT INTO documentos (usuario_id, tipo_documento, url_cloudinary, nombre_user) VALUES ($1, $2, $3, $4)', 
            [usuario_id, tipo_documento, req.file.path, nombre_user]
        );
        res.json({ message: 'Éxito', url: req.file.path });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- 6. RUTAS DE ADMIN ---

// Gestión de Empleados y Documentos Individuales
app.get('/api/admin/empleados', verificarToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'No autorizado' });
    const result = await pool.query("SELECT id, nombre_completo FROM usuarios WHERE rol = 'user'");
    res.json(result.rows);
});

app.get('/api/admin/documentos/:id', verificarToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'No autorizado' });
    const result = await pool.query('SELECT * FROM documentos WHERE usuario_id = $1', [req.params.id]);
    res.json(result.rows);
});

app.delete('/api/admin/documentos/:id', verificarToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'No autorizado' });
    try {
        const result = await pool.query('DELETE FROM documentos WHERE id = $1', [req.params.id]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'No encontrado' });
        res.json({ message: 'Registro eliminado correctamente' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- NUEVAS RUTAS: GESTIÓN EMPRESARIAL ---

// Obtener todos los documentos de la empresa
app.get('/api/admin/documentos-empresa', verificarToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'No autorizado' });
    try {
        const result = await pool.query('SELECT * FROM documentos_empresa ORDER BY id DESC');
        res.json(result.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Eliminar documento de empresa
app.delete('/api/admin/documentos-empresa/:id', verificarToken, async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'No autorizado' });
    try {
        const result = await pool.query('DELETE FROM documentos_empresa WHERE id = $1', [req.params.id]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'No encontrado' });
        res.json({ message: 'Documento empresarial eliminado' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Subir documento de empresa
app.post('/api/subir-empresa', verificarToken, upload.single('archivo'), async (req, res) => {
    if (req.user.rol !== 'admin') return res.status(403).json({ error: 'No autorizado' });
    const { tipo_documento } = req.body;
    try {
        await pool.query('INSERT INTO documentos_empresa (tipo_documento, url_cloudinary) VALUES ($1, $2)', [tipo_documento, req.file.path]);
        res.json({ message: 'Documento institucional guardado' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Manejo de errores Multer/PDF
app.use((err, req, res, next) => {
    if (err.message === 'SOLO_PDF_PERMITIDO') return res.status(400).json({ error: 'El archivo debe ser un PDF' });
    res.status(500).json({ error: err.message });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Servidor en puerto ${PORT}`));