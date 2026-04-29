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

app.use(
  cors({
    origin: APP_URL,
    credentials: true
  })
);

app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'change-me-demo-secret',
    resave: false,
    saveUninitialized: true
  })
);

app.use(express.static('public'));

app.use((req, res, next) => {
  console.log(
    `[${new Date().toISOString()}] ${req.method} ${req.url} - session user:`,
    req.session.userId || '(none)'
  );
  next();
});

// JWKS client for Keycloak
const jwks = jwksClient({
  jwksUri: `${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/certs`
});

function getKey(header, callback) {
  jwks.getSigningKey(header.kid, (err, key) => {
    if (err) {
      return callback(err);
    }
    const signingKey = key.getPublicKey();
    callback(null, signingKey);
  });
}

function verifyJwt(token) {
  const expectedIssuer = `${KEYCLOAK_URL}/realms/${REALM}`;
  const expectedAudience = CLIENT_ID;

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

// Безопасный /login: игнорируем user_id из браузера
app.post('/login', async (req, res) => {
  const { access_token } = req.body || {};

  if (!access_token) {
    return res.status(400).json({ error: 'access_token is required' });
  }

  try {
    const payload = await verifyJwt(access_token);

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
      message:
        'Logged in securely. Server ignored user_id from browser and used verified token payload.',
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

// /me: показывает пользователя из проверенного токена
app.get('/me', (req, res) => {
  if (!req.session.userId) {
    return res
      .status(401)
      .json({ error: 'Not logged in (no server-side session found)' });
  }

  return res.json({
    session_user: req.session.userId,
    note:
      'This value comes from verified token payload (sub/preferred_username/email). ' +
      'Server IGNORES any user_id provided by the browser.'
  });
});

// Сброс сессии
app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Error destroying session:', err);
      return res.status(500).json({ error: 'Failed to destroy session' });
    }
    return res.json({ message: 'Session destroyed' });
  });
});

// Статус сервера
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

app.listen(PORT, () => {
  console.log(`Secure demo server is running on ${APP_URL}`);
});
