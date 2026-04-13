// netlify/functions/analyse-logs.js
// RajaTech Solutions — Secure log analysis endpoint
//
// SETUP:
// 1. Set ANTHROPIC_API_KEY in Netlify environment variables
// 2. Set CLIENT_TOKENS in Netlify environment variables
//    Format: "clientA:token123,clientB:token456"
//    Generate tokens with: require('crypto').randomBytes(32).toString('hex')

// ── SECRET PATTERNS TO STRIP FROM LOGS ──────────────────────
// These patterns are removed before logs are sent to AI
const SECRET_PATTERNS = [
  // AWS keys
  /AKIA[0-9A-Z]{16}/g,
  // Generic API keys (long alphanumeric strings after key= or token=)
  /(api[_-]?key|token|secret|password|passwd|pwd|auth|bearer)\s*[:=]\s*['"]?([a-zA-Z0-9\-_\.]{8,})/gi,
  // GitHub tokens
  /gh[pousr]_[A-Za-z0-9_]{36,}/g,
  // Anthropic keys
  /sk-ant-[A-Za-z0-9\-_]{20,}/g,
  // JWT tokens
  /eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*/g,
  // Private keys / certs
  /-----BEGIN [A-Z ]+-----[\s\S]+?-----END [A-Z ]+-----/g,
  // Base64 encoded secrets (long strings)
  /(?:[A-Za-z0-9+/]{40,}={0,2})/g,
  // IP addresses (optional privacy)
  // /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,
  // Email addresses
  /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
];

function sanitiseLogs(rawLog) {
  let sanitised = rawLog;
  SECRET_PATTERNS.forEach(pattern => {
    sanitised = sanitised.replace(pattern, '[REDACTED]');
  });
  // Also replace GitHub Actions masked values (shown as ***)
  sanitised = sanitised.replace(/\*{3,}/g, '[MASKED]');
  return sanitised;
}

// ── TOKEN VALIDATION ─────────────────────────────────────────
function validateToken(token) {
  const tokenEnv = process.env.CLIENT_TOKENS || '';
  if (!tokenEnv) return { valid: false, client: null };

  const pairs = tokenEnv.split(',');
  for (const pair of pairs) {
    const [client, clientToken] = pair.trim().split(':');
    if (clientToken && clientToken.trim() === token) {
      return { valid: true, client: client.trim() };
    }
  }
  return { valid: false, client: null };
}

// ── RATE LIMITING (simple in-memory — resets on cold start) ──
const requestCounts = {};
const RATE_LIMIT = 20; // requests per hour per client

function checkRateLimit(client) {
  const now = Date.now();
  const hourAgo = now - 3600000;

  if (!requestCounts[client]) {
    requestCounts[client] = [];
  }

  // Remove entries older than 1 hour
  requestCounts[client] = requestCounts[client].filter(t => t > hourAgo);

  if (requestCounts[client].length >= RATE_LIMIT) {
    return false;
  }

  requestCounts[client].push(now);
  return true;
}

exports.handler = async (event) => {

  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type, X-Client-Token',
        'Access-Control-Allow-Methods': 'POST, OPTIONS'
      },
      body: ''
    };
  }

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method not allowed' };
  }

  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, X-Client-Token',
    'Content-Type': 'application/json'
  };

  // ── STEP 1: Validate client token ───────────────────────────
  const clientToken = event.headers['x-client-token'] || '';
  const { valid, client } = validateToken(clientToken);

  if (!valid) {
    return {
      statusCode: 401,
      headers,
      body: JSON.stringify({ error: 'Invalid or missing client token. Contact rajasekharking1205@gmail.com to get access.' })
    };
  }

  // ── STEP 2: Rate limit check ─────────────────────────────────
  if (!checkRateLimit(client)) {
    return {
      statusCode: 429,
      headers,
      body: JSON.stringify({ error: `Rate limit exceeded for client "${client}". Max ${RATE_LIMIT} analyses per hour.` })
    };
  }

  // ── STEP 3: Parse and validate request body ──────────────────
  let body;
  try {
    body = JSON.parse(event.body);
  } catch {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'Invalid JSON in request body.' })
    };
  }

  const { logs, context } = body;

  if (!logs || typeof logs !== 'string' || logs.trim().length < 10) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'Please provide log content in the "logs" field.' })
    };
  }

  // ── STEP 4: Sanitise logs — strip all secrets ────────────────
  const sanitisedLogs = sanitiseLogs(logs);

  // Limit log size to 8000 chars to avoid huge API costs
  const trimmedLogs = sanitisedLogs.length > 8000
    ? sanitisedLogs.slice(0, 8000) + '\n... [log truncated at 8000 chars]'
    : sanitisedLogs;

  // ── STEP 5: Build AI prompt ──────────────────────────────────
  const systemPrompt = `You are an expert DevOps engineer working for RajaTech Solutions (rajasekharking1205@gmail.com).
You are analysing CI/CD pipeline logs to diagnose failures and provide actionable fixes.

Always respond in this EXACT JSON format (no markdown, no extra text):
{
  "status": "failed" | "warning" | "success",
  "summary": "One sentence describing what happened",
  "root_cause": "Exact cause of the failure in 1-2 sentences",
  "errors": ["error line 1", "error line 2"],
  "fix": {
    "description": "What needs to be changed",
    "yaml": "Complete fixed YAML snippet if applicable, or empty string",
    "steps": ["Step 1", "Step 2", "Step 3"]
  },
  "prevention": "How to prevent this in future — one sentence",
  "severity": "critical" | "high" | "medium" | "low"
}`;

  const userMessage = `Analyse these CI/CD logs${context ? ` (context: ${context})` : ''}:

\`\`\`
${trimmedLogs}
\`\`\`

Provide diagnosis and fix in the exact JSON format specified.`;

  // ── STEP 6: Call Anthropic API ────────────────────────────────
  const apiKey = process.env.ANTHROPIC_API_KEY;

  if (!apiKey) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: 'Server not configured. Contact rajasekharking1205@gmail.com.' })
    };
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model:      'claude-sonnet-4-20250514',
        max_tokens: 2000,
        system:     systemPrompt,
        messages:   [{ role: 'user', content: userMessage }]
      })
    });

    const data = await response.json();

    if (!response.ok) {
      return {
        statusCode: response.status,
        headers,
        body: JSON.stringify({ error: data.error?.message || 'AI service error' })
      };
    }

    const rawText = data.content
      .filter(b => b.type === 'text')
      .map(b => b.text)
      .join('');

    // Parse the JSON response from AI
    let analysis;
    try {
      // Strip any accidental markdown fences
      const cleaned = rawText.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
      analysis = JSON.parse(cleaned);
    } catch {
      // If JSON parse fails, return raw text
      analysis = {
        status: 'unknown',
        summary: 'Analysis complete',
        root_cause: rawText,
        errors: [],
        fix: { description: '', yaml: '', steps: [] },
        prevention: '',
        severity: 'medium'
      };
    }

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        client,
        analysis,
        logs_sanitised: true,
        chars_analysed: trimmedLogs.length
      })
    };

  } catch (err) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: err.message })
    };
  }
};
