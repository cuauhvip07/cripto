

import dotenv from 'dotenv';
import express from 'express';
import bcrypt from 'bcryptjs';
import nodemailer from 'nodemailer';
import cors from 'cors';
import crypto from 'crypto';
import pkg from 'pg';
import jwt from 'jsonwebtoken';  // Usamos JWT para la autenticación

const { Pool } = pkg;  // Extraemos el Pool de `pkg`

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());  // Permite el acceso desde tu frontend

// Conexión a la base de datos (PostgreSQL)
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: 5432, // El puerto por defecto de PostgreSQL
});

// Crear el transporter para nodemailer
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',  // Usar el servidor SMTP de Gmail
  port: 587,  // Puerto TLS
  secure: false,  // Usar TLS (no SSL)
  auth: {
    user: process.env.EMAIL_USER,  // Tu correo de Gmail
    pass: process.env.EMAIL_PASS,  // La contraseña de aplicación generada
  },
});

// Función para generar un token aleatorio de 5 dígitos
const generateRandomToken = () => {
  return crypto.randomInt(10000, 99999).toString();  // Genera un número aleatorio de 5 dígitos
};

// Función para generar el par de llaves RSA (pública y privada)
const generarLlaves = () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });

  return { publicKey, privateKey };
};

// Middleware para verificar el token JWT
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(403).json({ message: 'No token provided' });
  }

  const tokenWithoutBearer = token.split(' ')[1];

  jwt.verify(tokenWithoutBearer, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Token no válido' });
    }
    req.user = user;  // Guarda la información del usuario (como su correo) en la solicitud
    next();
  });
};

// Ruta para registrar un usuario
app.post('/api/register', async (req, res) => {
  const { name, email, password, confirmPassword } = req.body;

  // Validaciones
  if (!name || !email || !password || !confirmPassword) {
    return res.status(400).json({ message: 'Todos los campos son requeridos' });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ message: 'Las contraseñas no coinciden' });
  }

  try {
    // Hashear la contraseña antes de almacenarla
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generar el token aleatorio de 5 dígitos
    const token = generateRandomToken();

    // Generar las llaves RSA
    const { publicKey, privateKey } = generarLlaves();

    // Insertar el usuario con las llaves y el token en la base de datos
    const query = 'INSERT INTO usuarios (nombre, correo, password, token, public_key, private_key) VALUES ($1, $2, $3, $4, $5, $6)';
    const values = [name, email, hashedPassword, token, publicKey, privateKey];

    await pool.query(query, values);

    // Respuesta con éxito
    res.status(200).json({ success: true, message: 'Usuario registrado correctamente' });

    // Enviar el correo con el token
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Verificación de correo',
      text: `Tu token de verificación es: ${token}`,
    };

    transporter.sendMail(mailOptions, (err, info) => {
      if (err) {
        console.error('Error al enviar correo:', err);
      } else {
        console.log('Correo enviado:', info.response);
      }
    });
  } catch (error) {
    console.error('Error al registrar el usuario:', error);
    res.status(500).json({ message: 'Error interno al registrar el usuario' });
  }
});

// Ruta para verificar el token de 5 dígitos
app.post('/api/verify-token', async (req, res) => {
  const { email, token } = req.body;

  if (!email || !token) {
    return res.status(400).json({ message: 'Email y token son requeridos' });
  }

  try {
    const query = 'SELECT token FROM usuarios WHERE correo = $1';
    const result = await pool.query(query, [email]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    const storedToken = result.rows[0].token;

    if (storedToken === token) {
      const jwtToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });
      return res.status(200).json({ success: true, message: 'Token válido', token: jwtToken });
    } else {
      return res.status(400).json({ message: 'Token inválido' });
    }
  } catch (error) {
    console.error('Error al verificar el token:', error);
    res.status(500).json({ message: 'Error interno' });
  }
});

// Ruta para obtener la llave pública
app.get('/api/get-public-key', authenticateToken, async (req, res) => {
  const email = req.user.email;

  try {
    const query = 'SELECT public_key FROM usuarios WHERE correo = $1';
    const result = await pool.query(query, [email]);

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
    }

    const publicKey = result.rows[0].public_key;
    res.json({ success: true, publicKey });  // Asegúrate de que esto esté en formato JSON
  } catch (error) {
    console.error('Error al obtener la llave pública:', error);
    res.status(500).json({ success: false, message: 'Error interno' });  // También devolver un JSON
  }
});



// Iniciar el servidor
const port = process.env.PORT || 4000;
app.listen(port, () => {
  console.log(`Servidor corriendo en el puerto ${port}`);
});

