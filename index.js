require('dotenv').config();

const express = require('express');
const cors = require('cors');

const app = express();

const PORT = process.env.PORT || 3000;
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;

app.use(cors({
  origin: APP_URL,
  credentials: false,
}));

app.use(express.json());

// Раздаём статические файлы из public/
app.use(express.static('public'));

// Простой "защищённый" API — требуется Authorization: Bearer <token>
app.get('/api/protected', (req, res) => {
  const authHeader = req.headers.authorization || '';

  if (!authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No or invalid Authorization header' });
  }

  const token = authHeader.substring('Bearer '.length);

  // В реальном проекте здесь нужно валидировать JWT (подпись, iss, aud и т.д.)
  // Сейчас — просто эхо, чтобы показать связку с фронтом.
  return res.json({
    message: 'Token received on backend',
    token,
  });
});

// Запуск сервера
app.listen(PORT, () => {
  console.log(`Server is running on ${APP_URL}`);
});
