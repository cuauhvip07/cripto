import dotenv from 'dotenv';
import express from 'express';
import bcrypt from 'bcryptjs';
import nodemailer from 'nodemailer';
import cors from 'cors'; // Para habilitar CORS
import crypto from 'crypto'; // Para generar un token aleatorio
import pg from 'pg';
const { Pool } = pg;


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

// Ruta para registrar usuario
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

    // Insertar el usuario y el token en la base de datos
    const query = 'INSERT INTO usuarios (nombre, correo, password, token) VALUES ($1, $2, $3, $4)';
    const values = [name, email, hashedPassword, token];

    const result = await pool.query(query, values);

    // Responder al cliente antes de enviar el correo
    res.status(200).send({ success: true });

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
    console.log('Error al registrar el usuario:', error);
    res.status(500).send('Error interno');
  }
});

// Ruta para verificar el token
app.post('/api/verify-token', async (req, res) => {
  const { email, token } = req.body; // También necesitamos el email del usuario

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
    console.log('Error al verificar el token:', error);
    res.status(500).send('Error interno');
  }
});

// Iniciar servidor
app.listen(4000, () => {
  console.log('Servidor corriendo en http://localhost:4000');
});