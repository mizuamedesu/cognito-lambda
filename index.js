const { JwtRsaVerifier } = require('aws-jwt-verify');

exports.handler = async (event) => {
  try {
    const body = JSON.parse(event.body || '{}');
    const token = body.token;

    if (!token) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'Token is required in the request body' })
      };
    }

    const userPoolId = process.env.USER_POOL_ID;
    const clientId = process.env.CLIENT_ID;

    if (!userPoolId) {
      return {
        statusCode: 500,
        body: JSON.stringify({ error: 'USER_POOL_ID environment variable is not set' })
      };
    }

    const verifier = JwtRsaVerifier.create({
      userPoolId: userPoolId,
      tokenUse: 'id',
      clientId: clientId
    });

    const payload = await verifier.verify(token);

    const email = payload.email;

    if (!email) {
      return {
        statusCode: 404,
        body: JSON.stringify({ error: 'Email not found in token payload' })
      };
    }

    return {
      statusCode: 200,
      body: JSON.stringify({ email })
    };

  } catch (error) {
    console.error('Error:', error);
    return {
      statusCode: 401,
      body: JSON.stringify({ error: 'Invalid token' })
    };
  }
};