require('dotenv').config();

const express = require('express');
const cors = require('cors');
const session = require('express-session');

const app = express();

const PORT = process.env.PORT || 3000;
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;

// Базовая диагностика окружения (используется в логах)
const keycloakConfig = {
  url: process.env.KEYCLOAK_URL,
  realm: process.env.KEYCLOAK_REALM,
  clientId: process.env.KEYCLOAK_CLIENT_ID
};

console.log('Keycloak configuration (server side):', keycloakConfig);

// CORS: разрешаем фронт-приложению обращаться к API
app.use(
  cors({
    origin: APP_URL,
    credentials: true
  })
);

// JSON body parser
app.use(express.json());

// Сессионное хранилище для демонстрации "серверной сессии"
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'change-me-demo-secret',
    resave: false,
    saveUninitialized: true
  })
);

// Раздача статических файлов (фронтенд/React/HTML)
app.use(express.static('public'));

// Простой логгер запросов
app.use((req, res, next) => {
  console.log(
    `[${new Date().toISOString()}] ${req.method} ${req.url} - session user:`,
    req.session.userId || '(none)'
  );
  next();
});

/**
 * УЯЗВИМАЯ ЛОГИКА
 *
 * POST /login
 * Тело:
 *   {
 *     "access_token": "...",
 *     "user_id": "attacker-or-victim"
 *   }
 *
 * Сервер НЕ проверяет токен и ДОВЕРЯЕТ user_id, пришедшему с фронта.
 * Это и есть демонстрируемая ошибка: сессию можно "переключить" на любого user_id.
 */
app.post('/login', (req, res) => {
  const { access_token, user_id } = req.body || {};

  if (!access_token || !user_id) {
    return res
      .status(400)
      .json({ error: 'access_token and user_id are required' });
  }

  // ПЛОХО: создаём сессию, просто доверяя тому, что прислал клиент
  req.session.userId = user_id;
  req.session.accessToken = access_token;

  console.log(
    'VULNERABLE LOGIN: session set to user_id =',
    req.session.userId
  );

  return res.json({
    message:
      'Logged in (vulnerable demo). Server trusted user_id from the browser.',
    session_user: req.session.userId
  });
});

/**
 * Диагностический маршрут, показывает, что сервер считает текущим пользователем.
 * Здесь видно, что session_user == тому user_id, который прислал клиент в /login,
 * вне зависимости от того, чей реально токен.
 */
app.get('/me', (req, res) => {
  if (!req.session.userId) {
    return res
      .status(401)
      .json({ error: 'Not logged in (no server-side session found)' });
  }

  return res.json({
    session_user: req.session.userId,
    note:
      'This value comes from user_id the frontend sent. ' +
      'Server did NOT verify that the token belongs to this user_id. ' +
      'This is exactly the incorrect Implicit Flow implementation described in chapter 3.'
  });
});

/**
 * Дополнительный маршрут для сброса сессии
 */
app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Error destroying session:', err);
      return res.status(500).json({ error: 'Failed to destroy session' });
    }
    return res.json({ message: 'Session destroyed' });
  });
});

/**
 * Статус сервера (для удобства проверки)
 */
app.get('/status', (req, res) => {
  res.json({
    ok: true,
    appUrl: APP_URL,
    keycloak: keycloakConfig,
    session_user: req.session.userId || null
  });
});

// Обработчик ошибок "по умолчанию"
app.use((err, req, res, next) => {
  console.error('Unhandled error in server:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Запуск
app.listen(PORT, () => {
  console.log(`Vulnerable demo server is running on ${APP_URL}`);
});
