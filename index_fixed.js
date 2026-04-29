require('dotenv').config();

const express = require('express');
const cors = require('cors');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const app = express();

const PORT = process.env.PORT || 3000;
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;

const KEYCLOAK_URL = process.env.KEYCLOAK_URL;
const REALM = process.env.KEYCLOAK_REALM;
const CLIENT_ID = process.env.KEYCLOAK_CLIENT_ID;

const keycloakConfig = {
  url: KEYCLOAK_URL,
  realm: REALM,
  clientId: CLIENT_ID
};

console.log('Keycloak configuration (server side):', keycloakConfig);

// CORS для фронта
app.use(
  cors({
    origin: APP_URL,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
  })
);

app.use(express.json());

// Сессии
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'change-me-demo-secret',
    resave: false,
    saveUninitialized: true,
    cookie: {
      httpOnly: true,
      secure: false,
      maxAge: 1000 * 60 * 60 // 1 час
    }
  })
);

// Логгер запросов
app.use((req, res, next) => {
  console.log(
    `[${new Date().toISOString()}] ${req.method} ${req.url} - session user:`,
    req.session.userId || '(none)'
  );
  next();
});

// JWKS клиент для проверки подписи токенов Keycloak
const jwks = jwksClient({
  jwksUri: `${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/certs`
});

// Получить ключ для конкретного kid
function getKey(header, callback) {
  jwks.getSigningKey(header.kid, (err, key) => {
    if (err) {
      return callback(err);
    }
    const signingKey = key.getPublicKey();
    callback(null, signingKey);
  });
}

// Верификация JWT от Keycloak
function verifyJwt(token, { expectedIssuer, expectedAudience }) {
  return new Promise((resolve, reject) => {
    jwt.verify(
      token,
      getKey,
      {
        algorithms: ['RS256'],
        issuer: expectedIssuer,
        audience: expectedAudience
      },
      (err, decoded) => {
        if (err) {
          return reject(err);
        }
        resolve(decoded);
      }
    );
  });
}

// Раздача статики
app.use(express.static('public'));

// УЯЗВИМЫЙ /login — оставляем для демонстрации ошибки
app.post('/login', (req, res) => {
  const { access_token, user_id } = req.body || {};

  if (!access_token || !user_id) {
    return res
      .status(400)
      .json({ error: 'access_token and user_id are required' });
  }

  // ПЛОХО: сервер доверяет user_id из браузера и не проверяет токен
  req.session.userId = user_id;
  req.session.accessToken = access_token;

  console.log('VULNERABLE LOGIN: session set to user_id =', req.session.userId);

  return res.json({
    message:
      'Logged in (vulnerable demo). Server trusted user_id from the browser.',
    session_user: req.session.userId
  });
});

// УЯЗВИМЫЙ /me — показывает, кого сервер считает текущим пользователем
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
      'This is the incorrect Implicit Flow implementation.'
  });
});

/**
 * БЕЗОПАСНЫЙ /login-secure
 *
 * Клиент присылает ТОЛЬКО access_token.
 * Сервер:
 *  1) проверяет подпись, issuer, audience и срок действия токена;
 *  2) берёт userId ТОЛЬКО из payload токена (sub/preferred_username/email);
 *  3) создаёт серверную сессию на основе этого userId.
 *
 * Никакой user_id из браузера не принимается — уязвимость закрыта. [file:91]
 */
app.post('/login-secure', async (req, res) => {
  const { access_token } = req.body || {};
  if (!access_token) {
    return res.status(400).json({ error: 'access_token is required' });
  }

  try {
    const expectedIssuer = `${KEYCLOAK_URL}/realms/${REALM}`;
    const expectedAudience = CLIENT_ID;

    const payload = await verifyJwt(access_token, {
      expectedIssuer,
      expectedAudience
    });

    const userId =
      payload.preferred_username || payload.email || payload.sub;

    if (!userId) {
      return res.status(400).json({
        error:
          'Token verified but no suitable user identifier (sub/preferred_username/email) found'
      });
    }

    req.session.userId = userId;
    req.session.accessToken = access_token;

    console.log('SECURE LOGIN: session set to userId =', userId);

    return res.json({
      message: 'Logged in securely (token verified and user taken from JWT)',
      session_user: userId,
      token_subject: payload.sub
    });
  } catch (err) {
    console.error('JWT verification failed:', err);
    return res.status(401).json({
      error: 'Invalid or expired access_token',
      details: err.message
    });
  }
});

/**
 * БЕЗОПАСНЫЙ /me-secure
 *
 * Показывает пользователя из серверной сессии, которая была создана
 * ТОЛЬКО после проверки токена в /login-secure.
 */
app.get('/me-secure', (req, res) => {
  if (!req.session.userId) {
    return res
      .status(401)
      .json({ error: 'Not logged in (no secure server-side session found)' });
  }

  return res.json({
    session_user: req.session.userId,
    note:
      'This user comes from verified token payload (sub/preferred_username), ' +
      'not from any user_id provided by the browser.'
  });
});

/**
 * Logout серверной сессии (общий для уязвимого и безопасного сценария)
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
 * Статус сервера
 */
app.get('/status', (req, res) => {
  res.json({
    ok: true,
    appUrl: APP_URL,
    keycloak: keycloakConfig,
    session_user: req.session.userId || null
  });
});

// Обработчик ошибок
app.use((err, req, res, next) => {
  console.error('Unhandled error in server:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Старт сервера
app.listen(PORT, () => {
  console.log(`Server is running on ${APP_URL}`);
});
