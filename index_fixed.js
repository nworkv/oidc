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

// Базовая диагностика окружения
const keycloakConfig = {
  url: KEYCLOAK_URL,
  realm: REALM,
  clientId: CLIENT_ID
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


// ======================
//  Проверка JWT Keycloak
// ======================

// JWKS клиент для получения публичных ключей Keycloak
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

// Проверка токена: подпись, issuer, audience, срок действия
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

/**
 * БЕЗОПАСНАЯ ЛОГИКА
 *
 * POST /login
 * Тело (как раньше, фронт не меняем):
 *   {
 *     "access_token": "...",
 *     "user_id": "attacker-or-victim"
 *   }
 *
 * НО: сервер теперь ПОЛНОСТЬЮ ИГНОРИРУЕТ user_id из тела.
 * Он:
 *  1) проверяет access_token (подпись, issuer, audience, срок);
 *  2) берёт userId ТОЛЬКО из payload токена (sub/preferred_username/email);
 *  3) создаёт сессию по этому userId.
 *
 * Таким образом, даже если злоумышленник подменит user_id на "victim",
 * сервер 
