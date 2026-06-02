# Изменения в реализации Implicit Flow и закрытие угрозы

## 1. Проблема в исходной реализации

В исходной версии backend‑сервера маршрут `POST /login` принимал из браузера сразу два параметра:

```json
{
  "access_token": "...",
  "user_id": "attacker-or-victim"
}
```

и создавал серверную сессию так:

```js
req.session.userId = user_id;
req.session.accessToken = access_token;
```

Сервер полностью доверял полю `user_id`, пришедшему с фронта, и **не проверял, соответствует ли этот идентификатор владельцу `access_token`**. Это позволяло злоумышленнику:

- легально получить свой токен (`access_token`);
- подставить в `user_id` идентификатор жертвы;
- получить серверную сессию от имени жертвы.

Именно это описано в работе как «некорректная реализация Implicit Flow» для классического клиент–серверного приложения.

---

## 2. Цель исправления

Цель изменений:

- сервер **никогда не доверяет `user_id` из браузера**;
- сервер сам определяет пользователя по **проверенному токену Keycloak**;
- при попытке подменить `user_id` сессия остаётся привязанной к владельцу токена, а не к жертве.

---

## 3. Добавлена проверка JWT от Keycloak

В `index.js` подключены библиотеки для проверки токена:

```js
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
```

Создаётся JWKS‑клиент для получения публичных ключей Keycloak:

```js
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
```

Функция `verifyJwt` проверяет:

- подпись токена (по публичному ключу Keycloak);
- `iss` (issuer) — совпадение с `KEYCLOAK_URL/realms/REALM`;
- `aud` (audience) — совпадение с `CLIENT_ID`;
- срок действия токена.

```js
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
```

---

## 4. Маршрут `/login`: игнорируем `user_id`, используем только токен

### Было (уязвимо)

```js
app.post('/login', (req, res) => {
  const { access_token, user_id } = req.body || {};

  if (!access_token || !user_id) {
    return res
      .status(400)
      .json({ error: 'access_token and user_id are required' });
  }

  // ПЛОХО: создаём сессию, доверяя user_id из браузера
  req.session.userId = user_id;
  req.session.accessToken = access_token;

  return res.json({
    message: 'Logged in (vulnerable demo). Server trusted user_id from the browser.',
    session_user: req.session.userId
  });
});
```

### Стало (безопасно)

```js
app.post('/login', async (req, res) => {
  const { access_token } = req.body || {};

  if (!access_token) {
    return res
      .status(400)
      .json({ error: 'access_token is required' });
  }

  try {
    // 1. Проверяем токен (подпись, issuer, audience, срок)
    const payload = await verifyJwt(access_token);

    // 2. Определяем пользователя только из payload токена
    const userId =
      payload.preferred_username || payload.email || payload.sub;

    if (!userId) {
      return res.status(400).json({
        error:
          'Token verified but no suitable user identifier (sub/preferred_username/email) found'
      });
    }

    // 3. Создаём серверную сессию по userId из токена
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
```

**Ключевые изменения:**

- из тела запроса берётся только `access_token`, поле `user_id` больше **не используется**;
- сервер обязательно проверяет JWT Keycloak;
- идентификатор пользователя (`userId`) берётся только из токена (`preferred_username` / `email` / `sub`);
- серверная сессия привязывается к владельцу токена, а не к внешнему `user_id`.

---

## 5. Маршрут `/me`: отражает защищённую привязку сессии

```js
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
```

Теперь:

- `session_user` всегда соответствует тому пользователю, который указан в проверенном токене;
- `/me` можно использовать для демонстрации, что после попытки «атаки» с подменой `user_id` сессия **не переключается** на жертву, а остаётся привязанной к владельцу токена.

---

## 6. Итог: уязвимость устранена

После внесённых изменений:

- невозможно получить сессию жертвы, просто подменив `user_id` в запросе `/login`;
- сервер не строит сессию на основании «`token` + `user_id` из браузера», как в уязвимой схеме;
- сервер следует рекомендациям из работы:
  - идентифицирует пользователя только по проверенному токену;
  - игнорирует любые `user_id`, присланные клиентом;
  - проверяет подпись, issuer, audience и срок действия токена.

Таким образом, уязвимость «некорректная реализация Implicit Flow» для классического клиент–серверного приложения на стенде считается закрытой.
