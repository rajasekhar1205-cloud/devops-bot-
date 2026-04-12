// netlify/functions/chat.js
// This runs on Netlify's server — your API key is NEVER exposed to the browser

exports.handler = async (event) => {

  // Only allow POST requests
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method not allowed' };
  }

  // CORS headers — allows your frontend to call this function
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json'
  };

  try {
    const { messages, system } = JSON.parse(event.body);

    // API key is read from Netlify Environment Variable
    // Set this in: Netlify Dashboard → Site → Environment Variables → ANTHROPIC_API_KEY
    const apiKey = process.env.ANTHROPIC_API_KEY;

    if (!apiKey) {
      return {
        statusCode: 500,
        headers,
        body: JSON.stringify({ error: 'API key not configured on server' })
      };
    }

    // Call Anthropic API from the server — key stays hidden
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1500,
        system,
        messages
      })
    });

    const data = await response.json();

    if (!response.ok) {
      return {
        statusCode: response.status,
        headers,
        body: JSON.stringify({ error: data.error?.message || 'API error' })
      };
    }

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify(data)
    };

  } catch (err) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: err.message })
    };
  }
};
