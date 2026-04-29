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
