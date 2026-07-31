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
  process.env.SUPABASE_URL &&
  (process.env.SUPABASE_SECRET_KEY ||
    process.env.SUPABASE_SERVICE_ROLE_KEY ||
    process.env.SUPABASE_KEY)
    ? createClient(
        process.env.SUPABASE_URL,
        process.env.SUPABASE_SECRET_KEY ||
          process.env.SUPABASE_SERVICE_ROLE_KEY ||
          process.env.SUPABASE_KEY,
        { auth: { persistSession: false, autoRefreshToken: false } }
      )
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

function getEasternDate() {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: 'America/New_York',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  })
    .formatToParts(new Date())
    .reduce((values, part) => ({ ...values, [part.type]: part.value }), {});
  return `${parts.year}-${parts.month}-${parts.day}`;
}

function adminKeyIsValid(req) {
  const configuredKey = process.env.DEV_ADMIN_KEY;
  const providedKey = req.get('x-admin-key');
  if (!configuredKey || !providedKey) return false;

  const configured = Buffer.from(configuredKey);
  const provided = Buffer.from(providedKey);
  return (
    configured.length === provided.length &&
    crypto.timingSafeEqual(configured, provided)
  );
}

async function syncSessionUser(user) {
  return supabase.from('users').upsert(
    {
      discord_id: user.id,
      display_name: user.name,
      avatar_url: user.avatar,
      last_login_at: new Date().toISOString(),
    },
    { onConflict: 'discord_id' }
  );
}

app.get('/', (req, res) => {
  res.sendFile(`${__dirname}/index.html`);
});

app.get('/qotd.html', (req, res) => {
  res.sendFile(`${__dirname}/qotd.html`);
});

app.get('/dev.html', (req, res) => {
  res.sendFile(`${__dirname}/dev.html`);
});

app.get('/leaderboard.html', (req, res) => {
  res.sendFile(`${__dirname}/leaderboard.html`);
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

    // Create the account on first login and refresh mutable Discord profile fields.
    if (supabase) {
      const { error } = await supabase.from('users').upsert(
        {
          discord_id: user.id,
          display_name: user.name,
          avatar_url: user.avatar,
          last_login_at: new Date().toISOString(),
        },
        { onConflict: 'discord_id' }
      );
      if (error) console.error('Could not save Discord user to Supabase:', error.message);
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

app.get('/api/leaderboard', async (req, res) => {
  if (!supabase) return res.status(503).json({ error: 'Database is not configured' });

  const requestedLimit = Number.parseInt(req.query.limit, 10);
  const limit = Number.isFinite(requestedLimit)
    ? Math.min(Math.max(requestedLimit, 1), 100)
    : 25;

  const { data, error } = await supabase
    .from('users')
    .select('discord_id, display_name, avatar_url, total_score, questions_answered')
    .order('total_score', { ascending: false })
    .order('questions_answered', { ascending: false })
    .limit(limit);

  if (error) {
    console.error('Leaderboard query failed:', error.message);
    return res.status(500).json({ error: 'Could not load leaderboard' });
  }

  res.json({ leaderboard: data });
});

app.get('/api/question/today/status', async (req, res) => {
  const session = readSession(req);
  if (!session) return res.status(401).json({ error: 'Log in first' });
  if (!supabase) return res.status(503).json({ error: 'Database is not configured' });

  const { data: question, error: questionError } = await supabase
    .from('questions')
    .select('id')
    .eq('active_date', getEasternDate())
    .maybeSingle();
  if (questionError) {
    console.error('Question status lookup failed:', questionError.message);
    return res.status(500).json({ error: 'Could not check today’s question' });
  }
  if (!question) return res.json({ hasQuestion: false, alreadyAnswered: false });

  const { data: attempt, error: attemptError } = await supabase
    .from('attempts')
    .select('id')
    .eq('discord_id', session.user.id)
    .eq('question_id', question.id)
    .maybeSingle();
  if (attemptError) {
    console.error('Answer status lookup failed:', attemptError.message);
    return res.status(500).json({ error: 'Could not check your answer status' });
  }

  res.json({ hasQuestion: true, alreadyAnswered: Boolean(attempt) });
});

app.get('/api/question/today', async (req, res) => {
  const session = readSession(req);
  if (!session) return res.status(401).json({ error: 'Log in before starting' });
  if (!supabase) return res.status(503).json({ error: 'Database is not configured' });

  const { error: userError } = await syncSessionUser(session.user);
  if (userError) {
    console.error('Question user sync failed:', userError.message);
    return res.status(500).json({ error: 'Could not sync your account' });
  }

  const { data, error } = await supabase
    .from('questions')
    .select('id, stimulus, question_prompt, choices, image_url, timer_seconds')
    .eq('active_date', getEasternDate())
    .maybeSingle();

  if (error) {
    console.error('Question query failed:', error.message);
    return res.status(500).json({ error: 'Could not load today’s question' });
  }
  if (!data) return res.status(404).json({ error: 'No question is scheduled for today' });

  const { data: priorAttempt, error: attemptError } = await supabase
    .from('attempts')
    .select('id')
    .eq('discord_id', session.user.id)
    .eq('question_id', data.id)
    .maybeSingle();
  if (attemptError) {
    console.error('Attempt status query failed:', attemptError.message);
    return res.status(500).json({ error: 'Could not check attempt status' });
  }

  let timeRemainingSeconds = null;
  if (data.timer_seconds) {
    const startedAt = new Date();
    const expiresAt = new Date(startedAt.getTime() + data.timer_seconds * 1000);
    const { error: startError } = await supabase.from('question_sessions').upsert(
      {
        discord_id: session.user.id,
        question_id: data.id,
        started_at: startedAt.toISOString(),
        expires_at: expiresAt.toISOString(),
      },
      { onConflict: 'discord_id,question_id', ignoreDuplicates: true }
    );
    if (startError) {
      console.error('Question timer start failed:', startError.message);
      return res.status(500).json({ error: 'Could not start question timer' });
    }

    const { data: questionSession, error: sessionError } = await supabase
      .from('question_sessions')
      .select('expires_at')
      .eq('discord_id', session.user.id)
      .eq('question_id', data.id)
      .single();
    if (sessionError) {
      console.error('Question timer query failed:', sessionError.message);
      return res.status(500).json({ error: 'Could not load question timer' });
    }
    timeRemainingSeconds = Math.max(
      0,
      Math.ceil((new Date(questionSession.expires_at).getTime() - Date.now()) / 1000)
    );
  }

  res.json({
    question: {
      id: data.id,
      stimulus: data.stimulus,
      prompt: data.question_prompt,
      choices: data.choices.map(({ label, text }) => ({ label, text })),
      imageUrl: data.image_url,
      timeLimitSeconds: timeRemainingSeconds,
      alreadyAnswered: Boolean(priorAttempt),
    },
  });
});

app.post('/api/dev/questions', async (req, res) => {
  if (!adminKeyIsValid(req)) return res.status(401).json({ error: 'Invalid developer key' });
  if (!supabase) return res.status(503).json({ error: 'Database is not configured' });

  const {
    id,
    stimulus,
    prompt,
    choices,
    expectedAnswer,
    points,
    activeDate,
    timerSeconds,
    imageUrl,
  } = req.body;

  const validChoices =
    Array.isArray(choices) &&
    choices.length >= 2 &&
    choices.every(
      (choice) =>
        typeof choice.label === 'string' &&
        typeof choice.text === 'string' &&
        typeof choice.explanation === 'string' &&
        choice.label.trim() &&
        choice.text.trim()
    );
  const labels = validChoices ? choices.map((choice) => choice.label.trim()) : [];

  if (
    typeof id !== 'string' ||
    !id.trim() ||
    typeof stimulus !== 'string' ||
    !stimulus.trim() ||
    typeof prompt !== 'string' ||
    !prompt.trim() ||
    !validChoices ||
    typeof expectedAnswer !== 'string' ||
    !labels.includes(expectedAnswer) ||
    typeof activeDate !== 'string' ||
    !/^\d{4}-\d{2}-\d{2}$/.test(activeDate)
  ) {
    return res.status(400).json({ error: 'Question fields are incomplete or invalid' });
  }

  const safePoints = Number.isInteger(points) && points >= 0 ? points : 100;
  const safeTimer =
    Number.isInteger(timerSeconds) && timerSeconds > 0 ? timerSeconds : null;

  const { data, error } = await supabase
    .from('questions')
    .upsert(
      {
        id: id.trim(),
        stimulus: stimulus.trim(),
        question_prompt: prompt.trim(),
        choices: choices.map((choice) => ({
          label: choice.label.trim(),
          text: choice.text.trim(),
          explanation: choice.explanation.trim(),
        })),
        expected_answer: expectedAnswer,
        points: safePoints,
        active_date: activeDate,
        timer_seconds: safeTimer,
        image_url: typeof imageUrl === 'string' && imageUrl.trim() ? imageUrl.trim() : null,
      },
      { onConflict: 'id' }
    )
    .select('id, active_date, timer_seconds')
    .single();

  if (error) {
    console.error('Developer question save failed:', error.message);
    return res.status(500).json({ error: error.message });
  }

  res.json({ question: data });
});

app.post('/api/answers', async (req, res) => {
  const session = readSession(req);
  if (!session) return res.status(401).json({ error: 'Log in before answering' });
  if (!supabase) return res.status(503).json({ error: 'Database is not configured' });

  const { questionId, answer } = req.body;
  if (typeof questionId !== 'string' || typeof answer !== 'string') {
    return res.status(400).json({ error: 'questionId and answer are required' });
  }

  // A user may still have a valid Discord cookie from before the database
  // tables were created. Ensure the referenced account exists before inserting
  // an attempt so the foreign-key constraint cannot fail for that reason.
  const { error: userError } = await syncSessionUser(session.user);

  if (userError) {
    console.error('Answer user sync failed:', {
      code: userError.code,
      message: userError.message,
      details: userError.details,
      hint: userError.hint,
    });
    return res.status(500).json({ error: 'Could not sync your account before saving' });
  }

  const { data, error } = await supabase.rpc('submit_answer', {
    p_discord_id: session.user.id,
    p_question_id: questionId,
    p_answer: answer,
  });

  if (error) {
    if (error.message.includes('already answered')) {
      return res.status(409).json({ error: 'You already answered this question' });
    }
    if (error.message.includes('question not found')) {
      return res.status(404).json({ error: 'Question not found' });
    }
    if (error.message.includes('time expired')) {
      return res.status(410).json({ error: 'Time expired before the answer was submitted' });
    }
    console.error('Answer submission failed:', {
      code: error.code,
      message: error.message,
      details: error.details,
      hint: error.hint,
    });
    return res.status(500).json({ error: 'Could not save answer' });
  }

  res.json(data);
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
