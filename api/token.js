const https = require('https');
const crypto = require('crypto');

const INTEGRATION_KEY = 'fa2466a9-cb58-4909-8db8-4be8b67abd1f';
const OAUTH_BASE      = 'account-d.docusign.com';
const API_BASE        = 'demo.docusign.net';
const ACCOUNT_ID      = '22e8c703-228d-4b5c-bc80-98311e1d264b';

module.exports = async (req, res) => {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if(req.method === 'OPTIONS'){
    return res.status(200).end();
  }
  if(req.method !== 'POST'){
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  const USER_ID         = process.env.DOCUSIGN_USER_ID;
  const PRIVATE_KEY_RAW = process.env.DOCUSIGN_PRIVATE_KEY;

  if(!USER_ID || !PRIVATE_KEY_RAW){
    return res.status(500).json({ error: 'Missing DOCUSIGN_USER_ID or DOCUSIGN_PRIVATE_KEY env vars' });
  }

  try{
    const token = await getJWTToken(USER_ID, PRIVATE_KEY_RAW);
    if(!token){
      return res.status(401).json({ error: 'Could not get access token — consent may be required' });
    }

    const body   = req.body || {};
    const action = body.action || 'token';

    if(action === 'token'){
      return res.status(200).json({ access_token: token, expires_in: 3600 });
    }

    if(action === 'createEnvelope'){
      const envResp = await apiRequest('POST',
        `/restapi/v2.1/accounts/${ACCOUNT_ID}/envelopes`,
        token, body.envelope
      );
      console.log('Envelope created:', envResp.data.envelopeId, 'status:', envResp.data.status);
      // Also fetch recipients to log their IDs
      if(envResp.data.envelopeId){
        const recResp = await apiRequest('GET',
          `/restapi/v2.1/accounts/${ACCOUNT_ID}/envelopes/${envResp.data.envelopeId}/recipients`,
          token, null
        );
        console.log('Recipients:', JSON.stringify(recResp.data).substring(0, 500));
        // Return recipients alongside envelope data so portal can use correct IDs
        return res.status(envResp.status).json({
          ...envResp.data,
          _recipients: recResp.data,
        });
      }
      return res.status(envResp.status).json(envResp.data);
    }

    if(action === 'recipientView'){
      const viewResp = await apiRequest('POST',
        `/restapi/v2.1/accounts/${ACCOUNT_ID}/envelopes/${body.envelopeId}/views/recipient`,
        token, body.viewRequest
      );
      return res.status(viewResp.status).json(viewResp.data);
    }

    // Get envelope status and recipient details
    if(action === 'getEnvelope'){
      const envResp = await apiRequest('GET',
        `/restapi/v2.1/accounts/${ACCOUNT_ID}/envelopes/${body.envelopeId}`,
        token, null
      );
      return res.status(envResp.status).json(envResp.data);
    }

    // Get combined signed PDF
    if(action === 'getDocuments'){
      const pdfResp = await apiRequestRaw('GET',
        `/restapi/v2.1/accounts/${ACCOUNT_ID}/envelopes/${body.envelopeId}/documents/combined`,
        token
      );
      // Return as base64 so we can handle it in the browser
      res.setHeader('Content-Type', 'application/json');
      return res.status(200).json({ pdf: pdfResp.toString('base64') });
    }

    return res.status(400).json({ error: 'Unknown action' });

  } catch(err){
    console.error('Error:', err.message);
    return res.status(500).json({ error: err.message });
  }
};

async function getJWTToken(userId, privateKeyRaw){
  // Clean up key — handle all newline formats
  let cleanKey = privateKeyRaw
    .replace(/\\n/g, '\n')
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .trim();

  // If key has no newlines, reconstruct it properly
  if(!cleanKey.includes('\n')){
    const begin = '-----BEGIN RSA PRIVATE KEY-----';
    const end   = '-----END RSA PRIVATE KEY-----';
    const b64   = cleanKey.replace(begin,'').replace(end,'').trim();
    const chunks = b64.match(/.{1,64}/g) || [];
    cleanKey = `${begin}\n${chunks.join('\n')}\n${end}`;
  }

  const now     = Math.floor(Date.now() / 1000);
  const header  = b64url(JSON.stringify({ alg:'RS256', typ:'JWT' }));
  const payload = b64url(JSON.stringify({
    iss: INTEGRATION_KEY, sub: userId, aud: OAUTH_BASE,
    iat: now, exp: now + 3600, scope: 'signature',
  }));
  const sigInput = `${header}.${payload}`;

  const sign = crypto.createSign('RSA-SHA256');
  sign.update(sigInput);
  sign.end();
  const signature = sign.sign({ key: cleanKey, format: 'pem' }, 'base64')
    .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');

  const jwt  = `${sigInput}.${signature}`;
  const body = `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`;
  const resp = await postReq(OAUTH_BASE, '/oauth/token', body);

  if(resp.data.error){
    console.error('JWT token error:', resp.data.error, resp.data.error_description);
    return null;
  }
  return resp.data.access_token || null;
}

function apiRequest(method, path, token, body){
  return new Promise((resolve, reject) => {
    const bodyStr = body ? JSON.stringify(body) : '';
    const headers = {
      'Authorization': `Bearer ${token}`,
      'Content-Type':  'application/json',
    };
    if(bodyStr) headers['Content-Length'] = Buffer.byteLength(bodyStr);
    const req = https.request({
      hostname: API_BASE, path, method, headers,
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try{ resolve({ status: res.statusCode, data: JSON.parse(data) }); }
        catch(e){ resolve({ status: res.statusCode, data: { raw: data } }); }
      });
    });
    req.on('error', reject);
    if(bodyStr) req.write(bodyStr);
    req.end();
  });
}

function apiRequestRaw(method, path, token){
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: API_BASE, path, method,
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/pdf',
      },
    }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
    });
    req.on('error', reject);
    req.end();
  });
}

function postReq(host, path, body){
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: host, path, method: 'POST',
      headers: {
        'Content-Type':   'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
      },
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try{ resolve({ status: res.statusCode, data: JSON.parse(data) }); }
        catch(e){ resolve({ status: res.statusCode, data: { raw: data } }); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function b64url(str){
  return Buffer.from(str).toString('base64')
    .replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}

// Already handled in main module.exports above
// This file is complete
