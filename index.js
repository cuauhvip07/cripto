import dotenv from 'dotenv';
import express from 'express';
import mysql from 'mysql2';
import bcrypt from 'bcryptjs';
import nodemailer from 'nodemailer';
import cors from 'cors'; // Para habilitar CORS
import crypto from 'crypto'; // Para generar un token aleatorio

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());  // Permite el acceso desde tu frontend

// Conexión a la base de datos
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
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
    const query = 'INSERT INTO usuarios (nombre, correo, password, token) VALUES (?, ?, ?, ?)';
    const values = [name, email, hashedPassword, token];

    db.query(query, values, (err, result) => {
      if (err) {
        console.log('Error al insertar en la base de datos:', err);
        return res.status(500).send('Error interno');
      }

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
    });
  } catch (error) {
    console.log('Error al registrar el usuario:', error);
    res.status(500).send('Error interno');
  }
});

// Ruta para verificar el token
app.post('/api/verify-token', (req, res) => {
  const { email, token } = req.body; // También necesitamos el email del usuario

  // Buscar el token en la base de datos
  const query = 'SELECT * FROM usuarios WHERE correo = ?';
  db.query(query, [email], (err, results) => {
    if (err) {
      return res.status(500).send('Error interno');
    }

    if (results.length === 0) {
      return res.status(404).send({ success: false, message: 'Usuario no encontrado' });
    }

    const user = results[0];

    // Verificar si el token es válido
    if (user.token === token) {
      // Marcar al usuario como verificado
      const updateQuery = 'UPDATE usuarios SET verificado = TRUE WHERE correo = ?';
      db.query(updateQuery, [email], (err, result) => {
        if (err) {
          return res.status(500).send('Error al actualizar la base de datos');
        }

        res.status(200).send({ success: true, message: 'Token verificado correctamente' });
      });
    } else {
      res.status(400).send({ success: false, message: 'Token inválido' });
    }
  });
});

// Iniciar servidor
app.listen(4000, () => {
  console.log('Servidor corriendo en http://localhost:4000');
});
