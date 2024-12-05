import dotenv from 'dotenv';
import express from 'express';
import bcrypt from 'bcryptjs';
import nodemailer from 'nodemailer';
import cors from 'cors'; // Para habilitar CORS
import crypto from 'crypto'; // Para generar las llaves RSA
import pkg from 'pg';  // Usamos la importación por defecto
const { Pool } = pkg;  // Extraemos el Pool de `pkg`
import fs from 'fs';
import path from 'path';
import { type } from 'os';
import { format } from 'path';

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

// Ruta para registrar un usuario
app.post('/api/register', async (req, res) => {
  const { name, email, password, confirmPassword } = req.body;

  // Validaciones
  if (!name || !email || !password || !confirmPassword) {
    return res.status(400).send({ message: 'Todos los campos son requeridos' });
  }

  if (password !== confirmPassword) {
    return res.status(400).send({ message: 'Las contraseñas no coinciden' });
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

    // Si todo es correcto, responder con éxito
    res.status(200).send({ success: true, message: 'Usuario registrado correctamente' });

    // Enviar el correo con el token
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Verificación de correo',
      text: `Tu token de verificación es: ${token}`,
    };

    // Enviar el correo de verificación
    transporter.sendMail(mailOptions, (err, info) => {
      if (err) {
        console.error('Error al enviar correo:', err);
      } else {
        console.log('Correo enviado:', info.response);
      }
    });
  } catch (error) {
    console.error('Error al registrar el usuario:', error);
    res.status(500).send({ message: 'Error interno al registrar el usuario', error: error.message });
  }
});

// Ruta para verificar el token
app.post('/api/verify-token', async (req, res) => {
  const { email, token } = req.body;

  try {
    // Buscar el token en la base de datos
    const query = 'SELECT * FROM usuarios WHERE correo = $1';
    const result = await pool.query(query, [email]);

    if (result.rows.length === 0) {
      return res.status(404).send({ success: false, message: 'Usuario no encontrado' });
    }

    const user = result.rows[0];

    // Verificar si el token es válido
    if (user.token === token) {
      // Marcar al usuario como verificado
      const updateQuery = 'UPDATE usuarios SET verificado = TRUE WHERE correo = $1';
      await pool.query(updateQuery, [email]);

      res.status(200).send({ success: true, message: 'Token verificado correctamente' });
    } else {
      res.status(400).send({ success: false, message: 'Token inválido' });
    }
  } catch (error) {
    console.error('Error al verificar el token:', error);
    res.status(500).send('Error interno');
  }
});

// Ruta para obtener la llave pública del usuario
app.get('/api/get-public-key', async (req, res) => {
  const { email } = req.query;

  try {
    // Buscar el usuario en la base de datos
    const query = 'SELECT public_key FROM usuarios WHERE correo = $1';
    const result = await pool.query(query, [email]);

    if (result.rows.length === 0) {
      return res.status(404).send({ success: false, message: 'Usuario no encontrado' });
    }

    // Devolver la llave pública del usuario
    res.status(200).send({ publicKey: result.rows[0].public_key });
  } catch (error) {
    console.error('Error al obtener la llave pública:', error);
    res.status(500).send('Error interno');
  }
});

// Ruta de prueba para asegurar que el servidor está funcionando
app.get('/api/ping', (req, res) => {
  res.status(200).send({ message: 'Servidor está funcionando' });
});

// Iniciar servidor
app.listen(4000, () => {
  console.log('Servidor corriendo en http://localhost:4000');
});
