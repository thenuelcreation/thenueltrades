import { createServer } from 'node:http';
import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
const { Pool } = pg;

const root = dirname(fileURLToPath(import.meta.url));
const dataDir = join(root, 'data');
const paymentsFile = join(dataDir, 'payments.json');
const accountsFile = join(dataDir, 'accounts.json');
const sessionsFile = join(dataDir, 'sessions.json');
mkdirSync(dataDir, { recursive: true });
if (!existsSync(paymentsFile)) writeFileSync(paymentsFile, '[]');
if (!existsSync(accountsFile)) writeFileSync(accountsFile, '[]');
if (!existsSync(sessionsFile)) writeFileSync(sessionsFile, '[]');
const pool = process.env.DATABASE_URL ? new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined }) : null;

const port = Number(process.env.PORT || 8787);
const appUrl = process.env.PUBLIC_APP_URL || 'http://localhost:5173';
const apiUrl = process.env.PUBLIC_API_URL || `http://localhost:${port}`;
const plans = {
  Monthly: Number(process.env.PLAN_MONTHLY_AMOUNT_KOBO || 50000),
  '3 months': Number(process.env.PLAN_3_MONTHS_AMOUNT_KOBO || 19000000),
  '6 months': Number(process.env.PLAN_6_MONTHS_AMOUNT_KOBO || 38000000),
  Yearly: Number(process.env.PLAN_YEARLY_AMOUNT_KOBO || 65000000),
};

const missingConfig = [
  !process.env.PAYSTACK_SECRET_KEY && 'PAYSTACK_SECRET_KEY',
  !plans.Monthly && 'PLAN_MONTHLY_AMOUNT_KOBO',
  !plans['3 months'] && 'PLAN_3_MONTHS_AMOUNT_KOBO',
  !plans['6 months'] && 'PLAN_6_MONTHS_AMOUNT_KOBO',
  !plans.Yearly && 'PLAN_YEARLY_AMOUNT_KOBO',
].filter(Boolean);

const json = file => JSON.parse(readFileSync(file, 'utf8'));
const save = (file, value) => writeFileSync(file, JSON.stringify(value, null, 2));
const send = (res, status, body, extraHeaders = {}) => { res.writeHead(status, { 'content-type': 'application/json', 'access-control-allow-origin': appUrl, 'access-control-allow-credentials': 'true', 'access-control-allow-headers': 'content-type', 'access-control-allow-methods': 'GET,POST,OPTIONS', ...extraHeaders }); res.end(JSON.stringify(body)); };
const body = req => new Promise((resolve, reject) => { let raw = ''; req.on('data', chunk => { raw += chunk; if (raw.length > 1000000) reject(new Error('Request too large')); }); req.on('end', () => { try { resolve(raw ? JSON.parse(raw) : {}) } catch { reject(new Error('Invalid JSON')) } }); });
const rawBody = req => new Promise((resolve, reject) => { let raw = ''; req.on('data', chunk => { raw += chunk; if (raw.length > 1000000) reject(new Error('Request too large')); }); req.on('end', () => resolve(raw)); });
const secret = (provider) => provider === 'paystack' ? process.env.PAYSTACK_SECRET_KEY : process.env.FLUTTERWAVE_SECRET_KEY;
const makeCode = () => `TNT-${randomBytes(2).toString('hex').toUpperCase()}-${randomBytes(2).toString('hex').toUpperCase()}`;
const hashPassword = password => { const salt = randomBytes(16).toString('hex'); return `${salt}:${scryptSync(password, salt, 64).toString('hex')}`; };
const verifyPassword = (password, stored) => { const [salt, hash] = stored.split(':'); const derived = scryptSync(password, salt, 64); return timingSafeEqual(derived, Buffer.from(hash, 'hex')); };
const cookieValue = (req, name) => (req.headers.cookie || '').split(';').map(item => item.trim().split('=')).find(([key]) => key === name)?.[1];
const cookieAttributes = appUrl.startsWith('https://') ? 'HttpOnly; SameSite=None; Secure; ' : 'HttpOnly; SameSite=Lax; ';
const sessionCookie = token => `${token}; ${cookieAttributes}Path=/; Max-Age=604800`;
const authError = message => Object.assign(new Error(message), { status: 401 });

async function initDatabase() {
  if (!pool) return;
  await pool.query(`CREATE TABLE IF NOT EXISTS payments (id BIGSERIAL PRIMARY KEY, provider TEXT NOT NULL, plan TEXT NOT NULL, email TEXT NOT NULL, reference TEXT UNIQUE NOT NULL, amount_kobo BIGINT NOT NULL, status TEXT NOT NULL, access_code TEXT UNIQUE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), paid_at TIMESTAMPTZ, code_used_at TIMESTAMPTZ)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS accounts (id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, plan TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
  await pool.query(`CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, email TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL)`);
}

const paymentFromRow = row => row && ({ provider: row.provider, plan: row.plan, email: row.email, reference: row.reference, amountKobo: Number(row.amount_kobo), status: row.status, accessCode: row.access_code, createdAt: row.created_at, paidAt: row.paid_at, codeUsedAt: row.code_used_at });
const accountFromRow = row => row && ({ name: row.name, username: row.username, email: row.email, passwordHash: row.password_hash, plan: row.plan, createdAt: row.created_at });
const accountForResponse = account => ({ name: account.name, username: account.username, email: account.email, plan: account.plan });

async function findPayment(provider, reference) {
  if (pool) return paymentFromRow((await pool.query('SELECT * FROM payments WHERE provider = $1 AND reference = $2', [provider, reference])).rows[0]);
  return json(paymentsFile).find(item => item.reference === reference && item.provider === provider) || null;
}
async function findAvailablePaymentByCode(accessCode) {
  const normalizedCode = accessCode.trim().toUpperCase();
  if (pool) return paymentFromRow((await pool.query('SELECT * FROM payments WHERE access_code = $1 AND status = $2 AND code_used_at IS NULL', [normalizedCode, 'paid'])).rows[0]);
  return json(paymentsFile).find(item => item.accessCode === normalizedCode && item.status === 'paid' && !item.codeUsedAt) || null;
}
async function insertPayment(payment) {
  if (pool) { await pool.query('INSERT INTO payments (provider, plan, email, reference, amount_kobo, status) VALUES ($1, $2, $3, $4, $5, $6)', [payment.provider, payment.plan, payment.email, payment.reference, payment.amountKobo, payment.status]); return; }
  const payments = json(paymentsFile); payments.push(payment); save(paymentsFile, payments);
}
async function markPaymentPaid(payment) {
  if (payment.status === 'paid') return payment;
  const accessCode = payment.accessCode || makeCode(); const paidAt = new Date().toISOString();
  if (pool) await pool.query('UPDATE payments SET status = $1, access_code = $2, paid_at = $3 WHERE provider = $4 AND reference = $5', ['paid', accessCode, paidAt, payment.provider, payment.reference]);
  else { const payments = json(paymentsFile); const stored = payments.find(item => item.reference === payment.reference && item.provider === payment.provider); stored.status = 'paid'; stored.accessCode = accessCode; stored.paidAt = paidAt; save(paymentsFile, payments); }
  return { ...payment, status: 'paid', accessCode, paidAt };
}
async function accountForRequest(req) {
  const token = cookieValue(req, 'tnt_session'); if (!token) return null;
  if (pool) return accountFromRow((await pool.query('SELECT a.* FROM accounts a JOIN sessions s ON s.email = a.email WHERE s.token = $1 AND s.expires_at > NOW()', [token])).rows[0]);
  const session = json(sessionsFile).find(item => item.token === token && Date.parse(item.expiresAt) > Date.now()); if (!session) return null; return json(accountsFile).find(account => account.email === session.email) || null;
}
const api = (provider) => provider === 'paystack' ? 'https://api.paystack.co' : 'https://api.flutterwave.com/v3';
const headers = provider => ({ Authorization: `Bearer ${secret(provider)}`, 'content-type': 'application/json' });

async function providerRequest(provider, path, options = {}) {
  const response = await fetch(`${api(provider)}${path}`, { ...options, headers: { ...headers(provider), ...(options.headers || {}) } });
  const result = await response.json();
  if (!response.ok || result.status === false) throw new Error(result.message || `Provider request failed (${response.status})`);
  return result;
}

function requireProvider(provider) {
  if (!['paystack', 'flutterwave'].includes(provider)) throw new Error('Provider must be paystack or flutterwave');
  if (!secret(provider)) throw new Error(`${provider.toUpperCase()} secret key is not configured`);
}

async function initializePayment(input) {
  const { provider, plan, email } = input;
  requireProvider(provider);
  const amountKobo = plans[plan];
  if (!amountKobo) throw new Error(`Price for ${plan} is not configured`);
  if (!email || !/^\S+@\S+\.\S+$/.test(email)) throw new Error('A valid email is required');
  const reference = `TNT_${Date.now()}_${randomBytes(4).toString('hex')}`;
  let result;
  if (provider === 'paystack') {
    result = await providerRequest(provider, '/transaction/initialize', { method: 'POST', body: JSON.stringify({ email, amount: amountKobo, currency: 'NGN', reference, callback_url: `${apiUrl}/api/payments/callback?provider=paystack&reference=${reference}`, metadata: { plan } }) });
  } else {
    result = await providerRequest(provider, '/payments', { method: 'POST', body: JSON.stringify({ tx_ref: reference, amount: amountKobo / 100, currency: 'NGN', redirect_url: `${apiUrl}/api/payments/callback?provider=flutterwave`, payment_options: 'card,banktransfer,ussd', customer: { email }, meta: { plan } }) });
  }
  await insertPayment({ provider, plan, email: email.trim().toLowerCase(), reference, amountKobo, status: 'pending', createdAt: new Date().toISOString() });
  const checkoutUrl = provider === 'paystack' ? result.data.authorization_url : result.data.link;
  return { checkoutUrl, reference };
}

async function verifyPayment(provider, reference, transactionId) {
  requireProvider(provider);
  const payment = await findPayment(provider, reference);
  if (!payment) throw new Error('Payment reference was not found');
  const result = provider === 'paystack'
    ? await providerRequest(provider, `/transaction/verify/${encodeURIComponent(reference)}`)
    : await providerRequest(provider, `/transactions/${encodeURIComponent(transactionId)}/verify`);
  const paid = provider === 'paystack'
    ? result.data.status === 'success'
      && result.data.reference === reference
      && result.data.amount === payment.amountKobo
      && result.data.currency === 'NGN'
    : result.data.status === 'successful'
      && result.data.tx_ref === reference
      && Number(result.data.amount) === payment.amountKobo / 100
      && result.data.currency === 'NGN';
  if (!paid) throw new Error('Payment has not been confirmed');
  return markPaymentPaid(payment);
}

async function handle(req, res) {
  if (req.method === 'OPTIONS') return send(res, 204, {});
  try {
    if (req.method === 'POST' && req.url === '/api/payments/initialize') return send(res, 200, await initializePayment(await body(req)));
    if (req.method === 'POST' && req.url === '/api/payments/verify') { const input = await body(req); return send(res, 200, await verifyPayment(input.provider, input.reference, input.transactionId)); }
    if (req.method === 'POST' && req.url === '/api/webhooks/paystack') {
      const raw = await rawBody(req); const signature = req.headers['x-paystack-signature']; const expected = createHmac('sha512', process.env.PAYSTACK_SECRET_KEY || '').update(raw).digest('hex'); if (!signature || signature !== expected) throw new Error('Invalid Paystack webhook signature'); const event = JSON.parse(raw); if (event.event === 'charge.success') await verifyPayment('paystack', event.data.reference); return send(res, 200, { received: true });
    }
    if (req.method === 'POST' && req.url === '/api/webhooks/flutterwave') {
      const raw = await rawBody(req); const expected = process.env.FLUTTERWAVE_WEBHOOK_SECRET_HASH; if (!expected || req.headers['verif-hash'] !== expected) throw new Error('Invalid Flutterwave webhook signature'); const event = JSON.parse(raw); if (event.event === 'charge.completed' && event.data?.status === 'successful') await verifyPayment('flutterwave', event.data.tx_ref, event.data.id); return send(res, 200, { received: true });
    }
    if (req.method === 'POST' && req.url === '/api/auth/login') {
      const input = await body(req); const identifier = String(input.identifier || '').trim().toLowerCase(); const password = String(input.password || '');
      if (!identifier || !password) throw authError('Enter your username or email and password');
      const account = pool ? accountFromRow((await pool.query('SELECT * FROM accounts WHERE LOWER(email) = $1 OR LOWER(username) = $1', [identifier])).rows[0]) : json(accountsFile).find(item => item.email.toLowerCase() === identifier || item.username.toLowerCase() === identifier);
      if (!account || !verifyPassword(password, account.passwordHash)) throw authError('Invalid username/email or password');
      const token = randomBytes(32).toString('hex'); const expiresAt = new Date(Date.now() + 604800000).toISOString(); if (pool) await pool.query('INSERT INTO sessions (token, email, expires_at) VALUES ($1, $2, $3)', [token, account.email, expiresAt]); else { const sessions = json(sessionsFile); sessions.push({ token, email: account.email, expiresAt }); save(sessionsFile, sessions); }
      return send(res, 200, { ok: true, account: accountForResponse(account) }, { 'set-cookie': `tnt_session=${sessionCookie(token)}` });
    }
    if (req.method === 'GET' && req.url === '/api/auth/me') {
      const account = await accountForRequest(req); if (!account) throw authError('Authentication required');
      return send(res, 200, { authenticated: true, account: accountForResponse(account) });
    }
    if (req.method === 'POST' && req.url === '/api/auth/logout') {
      const token = cookieValue(req, 'tnt_session'); if (pool) await pool.query('DELETE FROM sessions WHERE token = $1', [token]); else { const sessions = json(sessionsFile).filter(item => item.token !== token); save(sessionsFile, sessions); }
      return send(res, 200, { ok: true }, { 'set-cookie': `tnt_session=; ${cookieAttributes}Path=/; Max-Age=0` });
    }
    if (req.method === 'POST' && req.url === '/api/accounts') {
      const input = await body(req); if (!input.name || !input.username || !input.email || !input.password || !input.accessCode) throw new Error('All account fields are required');
      const payment = await findAvailablePaymentByCode(input.accessCode); if (!payment) throw new Error('Invalid or already-used membership access code');
      const email = input.email.trim().toLowerCase(); const username = input.username.trim().toLowerCase(); if (pool) { const existing = await pool.query('SELECT 1 FROM accounts WHERE username = $1 OR email = $2', [username, email]); if (existing.rowCount) throw new Error('Username or email already exists'); await pool.query('INSERT INTO accounts (name, username, email, password_hash, plan) VALUES ($1, $2, $3, $4, $5)', [input.name.trim(), username, email, hashPassword(input.password), payment.plan]); await pool.query('UPDATE payments SET code_used_at = NOW() WHERE provider = $1 AND reference = $2', [payment.provider, payment.reference]); } else { const accounts = json(accountsFile); if (accounts.some(account => account.username === username || account.email === email)) throw new Error('Username or email already exists'); accounts.push({ name: input.name.trim(), username, email, passwordHash: hashPassword(input.password), plan: payment.plan, createdAt: new Date().toISOString() }); payment.codeUsedAt = new Date().toISOString(); const payments = json(paymentsFile); const stored = payments.find(item => item.reference === payment.reference && item.provider === payment.provider); stored.codeUsedAt = payment.codeUsedAt; save(accountsFile, accounts); save(paymentsFile, payments); } return send(res, 201, { ok: true });
    }
    if (req.method === 'GET' && req.url?.startsWith('/api/payments/callback')) {
      const url = new URL(req.url, `http://${req.headers.host}`); const provider = url.searchParams.get('provider'); const reference = url.searchParams.get('reference') || url.searchParams.get('tx_ref'); const transactionId = url.searchParams.get('transaction_id'); const payment = await verifyPayment(provider, reference, transactionId); return res.writeHead(302, { location: `${appUrl}/#payment-success?code=${encodeURIComponent(payment.accessCode)}&plan=${encodeURIComponent(payment.plan)}` }).end();
    }
    return send(res, 404, { error: 'Not found' });
  } catch (error) { return send(res, error.status || 400, { error: error.message }); }
}

initDatabase().then(() => createServer(handle).listen(port, () => {
  console.log(`Payment backend listening on http://localhost:${port}`);
  console.log(`Storage: ${pool ? 'PostgreSQL' : 'local JSON fallback (set DATABASE_URL for production)'}`);
  if (missingConfig.length) console.warn(`Missing configuration: ${missingConfig.join(', ')}`);
  else console.log('Paystack and Flutterwave configuration loaded.');
})).catch(error => { console.error('Unable to initialize storage:', error); process.exit(1); });
