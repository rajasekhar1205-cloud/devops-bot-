// netlify/functions/generate-token.js
// RajaTech Solutions — Admin utility to generate client access tokens
//
// USAGE: Call this endpoint with your admin password to generate a token for a new client
// POST /.netlify/functions/generate-token
// Body: { "admin_password": "your_admin_password", "client_name": "StartupXYZ" }
//
// Set ADMIN_PASSWORD in Netlify environment variables

const crypto = require('crypto');

exports.handler = async (event) => {

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method not allowed' };
  }

  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Content-Type': 'application/json'
  };

  try {
    const { admin_password, client_name } = JSON.parse(event.body);

    // Validate admin password
    const adminPass = process.env.ADMIN_PASSWORD;
    if (!adminPass || admin_password !== adminPass) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: 'Invalid admin password.' })
      };
    }

    if (!client_name || client_name.trim().length < 2) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: 'Please provide a client_name.' })
      };
    }

    // Generate a secure random token
    const token = crypto.randomBytes(32).toString('hex');
    const clientKey = client_name.trim().toLowerCase().replace(/[^a-z0-9]/g, '_');

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        client:  clientKey,
        token,
        // Add this to CLIENT_TOKENS environment variable in Netlify
        // Format: existing_tokens,clientKey:token
        add_to_env: `${clientKey}:${token}`,
        instructions: [
          `1. Copy the "add_to_env" value above`,
          `2. Go to Netlify → Site → Environment Variables → CLIENT_TOKENS`,
          `3. Append ,${clientKey}:${token} to the existing value`,
          `4. Redeploy the site`,
          `5. Give the client their token: ${token}`,
          `6. Client sends header: X-Client-Token: ${token}`
        ]
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
