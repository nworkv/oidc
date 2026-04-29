Была проверка по user_id:
<code>
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
  ...
});</code>

Стала полновенная проверка полей запроса:

<code>
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const jwks = jwksClient({
  jwksUri: `${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/certs`
});

function getKey(header, callback) { ... }

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
      (err, decoded) => { ... }
    );
  });
}
</code>
