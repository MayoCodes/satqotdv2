const crypto = require('crypto');
const express = require('express');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === 'production';

if (isProduction) {
  app.set('trust proxy', 1);
}

app.use(express.json());

const supabase =
  process.env.SUPABASE_URL && process.env.SUPABASE_KEY
    ? createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY)
    : null;

const sessionSecret = process.env.SESSION_SECRET;

function parseCookies(req) {
  return Object.fromEntries(
    (req.headers.cookie || '')
      .split(';')
      .filter(Boolean)
      .map((cookie) => {
        const separator = cookie.indexOf('=');
        return [
          decodeURIComponent(cookie.slice(0, separator).trim()),
          decodeURIComponent(cookie.slice(separator + 1)),
        ];
      })
  );
}

function sign(value) {
  return crypto.createHmac('sha256', sessionSecret).update(value).digest('base64url');
}

function createSession(user) {
  const payload = Buffer.from(
    JSON.stringify({ user, expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000 })
  ).toString('base64url');
  return `${payload}.${sign(payload)}`;
}

function readSession(req) {
  if (!sessionSecret) return null;
  const token = parseCookies(req).sat_session;
  if (!token) return null;

  const [payload, signature] = token.split('.');
  if (!payload || !signature) return null;

  const expected = sign(payload);
  const actualBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);
  if (
    actualBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(actualBuffer, expectedBuffer)
  ) {
    return null;
  }

  try {
    const session = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return session.expiresAt > Date.now() ? session : null;
  } catch {
    return null;
  }
}

function cookieOptions(maxAge) {
  return {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
    path: '/',
    maxAge,
  };
}

function getRedirectUri(req) {
  return (
    process.env.DISCORD_REDIRECT_URI ||
    `${req.protocol}://${req.get('host')}/auth/discord/callback`
  );
}

function discordAvatar(user) {
  if (user.avatar) {
    const extension = user.avatar.startsWith('a_') ? 'gif' : 'png';
    return `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.${extension}?size=128`;
  }

  const index = Number((BigInt(user.id) >> 22n) % 6n);
  return `https://cdn.discordapp.com/embed/avatars/${index}.png`;
}

app.get('/', (req, res) => {
  res.sendFile(`${__dirname}/index.html`);
});

app.get('/qotd.html', (req, res) => {
  res.sendFile(`${__dirname}/qotd.html`);
});

app.get('/auth/discord', (req, res) => {
  if (!process.env.DISCORD_CLIENT_ID || !process.env.DISCORD_CLIENT_SECRET || !sessionSecret) {
    return res.status(503).send('Discord login is not configured yet.');
  }

  const state = crypto.randomBytes(24).toString('base64url');
  res.cookie('discord_oauth_state', state, cookieOptions(10 * 60 * 1000));

  const params = new URLSearchParams({
    client_id: process.env.DISCORD_CLIENT_ID,
    redirect_uri: getRedirectUri(req),
    response_type: 'code',
    scope: 'identify',
    state,
    prompt: 'consent',
  });
  res.redirect(`https://discord.com/oauth2/authorize?${params}`);
});

app.get('/auth/discord/callback', async (req, res) => {
  const storedState = parseCookies(req).discord_oauth_state;
  res.clearCookie('discord_oauth_state', cookieOptions(0));

  if (!req.query.code || !req.query.state || req.query.state !== storedState) {
    return res.redirect('/?login_error=invalid_state');
  }

  try {
    const tokenResponse = await fetch('https://discord.com/api/v10/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID,
        client_secret: process.env.DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code: req.query.code,
        redirect_uri: getRedirectUri(req),
      }),
    });
    if (!tokenResponse.ok) throw new Error(`Token exchange failed (${tokenResponse.status})`);
    const token = await tokenResponse.json();

    const userResponse = await fetch('https://discord.com/api/v10/users/@me', {
      headers: { Authorization: `Bearer ${token.access_token}` },
    });
    if (!userResponse.ok) throw new Error(`User request failed (${userResponse.status})`);
    const discordUser = await userResponse.json();

    const user = {
      id: discordUser.id,
      name: discordUser.global_name || discordUser.username,
      avatar: discordAvatar(discordUser),
    };

    res.cookie('sat_session', createSession(user), cookieOptions(7 * 24 * 60 * 60 * 1000));

    // Keep the existing name collection working without making login depend on it.
    if (supabase) {
      const { error } = await supabase.from('user_names').insert([{ name: user.name }]);
      if (error) console.error('Could not save Discord name to Supabase:', error.message);
    }

    res.redirect('/');
  } catch (error) {
    console.error('Discord OAuth error:', error);
    res.redirect('/?login_error=discord');
  }
});

app.get('/api/me', (req, res) => {
  const session = readSession(req);
  if (!session) return res.status(401).json({ user: null });
  res.json({ user: session.user });
});

app.post('/auth/logout', (req, res) => {
  res.clearCookie('sat_session', cookieOptions(0));
  res.status(204).end();
});

if (require.main === module) {
  app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
  });
}

module.exports = app;
