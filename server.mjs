import { createServer } from 'node:http';
import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(fileURLToPath(import.meta.url));
const dataDir = join(root, 'data');
const paymentsFile = join(dataDir, 'payments.json');
const accountsFile = join(dataDir, 'accounts.json');
mkdirSync(dataDir, { recursive: true });
if (!existsSync(paymentsFile)) writeFileSync(paymentsFile, '[]');
if (!existsSync(accountsFile)) writeFileSync(accountsFile, '[]');

const port = Number(process.env.PORT || 8787);
const appUrl = process.env.PUBLIC_APP_URL || 'http://localhost:5173';
const apiUrl = process.env.PUBLIC_API_URL || `http://localhost:${port}`;
const plans = {
  Monthly: Number(process.env.PLAN_MONTHLY_AMOUNT_CENTS || 9000),
  '3 months': Number(process.env.PLAN_3_MONTHS_AMOUNT_CENTS || 19000),
  '6 months': Number(process.env.PLAN_6_MONTHS_AMOUNT_CENTS || 38000),
  Yearly: Number(process.env.PLAN_YEARLY_AMOUNT_CENTS || 65000),
};

const missingConfig = [
  !process.env.PAYSTACK_SECRET_KEY && 'PAYSTACK_SECRET_KEY',
  !plans.Monthly && 'PLAN_MONTHLY_AMOUNT_CENTS',
  !plans['3 months'] && 'PLAN_3_MONTHS_AMOUNT_CENTS',
  !plans['6 months'] && 'PLAN_6_MONTHS_AMOUNT_CENTS',
  !plans.Yearly && 'PLAN_YEARLY_AMOUNT_CENTS',
].filter(Boolean);

const json = file => JSON.parse(readFileSync(file, 'utf8'));
const save = (file, value) => writeFileSync(file, JSON.stringify(value, null, 2));
const send = (res, status, body) => { res.writeHead(status, { 'content-type': 'application/json', 'access-control-allow-origin': appUrl, 'access-control-allow-headers': 'content-type', 'access-control-allow-methods': 'GET,POST,OPTIONS' }); res.end(JSON.stringify(body)); };
const body = req => new Promise((resolve, reject) => { let raw = ''; req.on('data', chunk => { raw += chunk; if (raw.length > 1000000) reject(new Error('Request too large')); }); req.on('end', () => { try { resolve(raw ? JSON.parse(raw) : {}) } catch { reject(new Error('Invalid JSON')) } }); });
const rawBody = req => new Promise((resolve, reject) => { let raw = ''; req.on('data', chunk => { raw += chunk; if (raw.length > 1000000) reject(new Error('Request too large')); }); req.on('end', () => resolve(raw)); });
const secret = (provider) => provider === 'paystack' ? process.env.PAYSTACK_SECRET_KEY : process.env.FLUTTERWAVE_SECRET_KEY;
const makeCode = () => `TNT-${randomBytes(2).toString('hex').toUpperCase()}-${randomBytes(2).toString('hex').toUpperCase()}`;
const hashPassword = password => { const salt = randomBytes(16).toString('hex'); return `${salt}:${scryptSync(password, salt, 64).toString('hex')}`; };
const verifyPassword = (password, stored) => { const [salt, hash] = stored.split(':'); const derived = scryptSync(password, salt, 64); return timingSafeEqual(derived, Buffer.from(hash, 'hex')); };
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
    result = await providerRequest(provider, '/transaction/initialize', { method: 'POST', body: JSON.stringify({ email, amount: amountKobo, currency: 'USD', reference, callback_url: `${apiUrl}/api/payments/callback?provider=paystack&reference=${reference}`, metadata: { plan } }) });
  } else {
    result = await providerRequest(provider, '/payments', { method: 'POST', body: JSON.stringify({ tx_ref: reference, amount: amountKobo / 100, currency: 'USD', redirect_url: `${apiUrl}/api/payments/callback?provider=flutterwave`, payment_options: 'card,banktransfer,ussd', customer: { email }, meta: { plan } }) });
  }
  const payments = json(paymentsFile);
  payments.push({ provider, plan, email, reference, amountKobo, status: 'pending', createdAt: new Date().toISOString() });
  save(paymentsFile, payments);
  const checkoutUrl = provider === 'paystack' ? result.data.authorization_url : result.data.link;
  return { checkoutUrl, reference };
}

async function verifyPayment(provider, reference, transactionId) {
  requireProvider(provider);
  const payments = json(paymentsFile);
  const payment = payments.find(item => item.reference === reference && item.provider === provider);
  if (!payment) throw new Error('Payment reference was not found');
  const result = provider === 'paystack'
    ? await providerRequest(provider, `/transaction/verify/${encodeURIComponent(reference)}`)
    : await providerRequest(provider, `/transactions/${encodeURIComponent(transactionId)}/verify`);
  const paid = provider === 'paystack'
    ? result.data.status === 'success'
      && result.data.reference === reference
      && result.data.amount === payment.amountKobo
      && result.data.currency === 'USD'
    : result.data.status === 'successful'
      && result.data.tx_ref === reference
      && Number(result.data.amount) === payment.amountKobo / 100
      && result.data.currency === 'USD';
  if (!paid) throw new Error('Payment has not been confirmed');
  if (payment.status !== 'paid') { payment.status = 'paid'; payment.accessCode = payment.accessCode || makeCode(); payment.paidAt = new Date().toISOString(); save(paymentsFile, payments); }
  return payment;
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
    if (req.method === 'POST' && req.url === '/api/accounts') {
      const input = await body(req); if (!input.name || !input.username || !input.email || !input.password || !input.accessCode) throw new Error('All account fields are required');
      const payments = json(paymentsFile); const payment = payments.find(item => item.accessCode === input.accessCode && item.status === 'paid' && !item.codeUsedAt); if (!payment) throw new Error('Invalid or already-used membership access code');
      const accounts = json(accountsFile); if (accounts.some(account => account.username === input.username || account.email === input.email)) throw new Error('Username or email already exists');
      accounts.push({ name: input.name, username: input.username, email: input.email, passwordHash: hashPassword(input.password), plan: payment.plan, createdAt: new Date().toISOString() }); payment.codeUsedAt = new Date().toISOString(); save(accountsFile, accounts); save(paymentsFile, payments); return send(res, 201, { ok: true });
    }
    if (req.method === 'GET' && req.url?.startsWith('/api/payments/callback')) {
      const url = new URL(req.url, `http://${req.headers.host}`); const provider = url.searchParams.get('provider'); const reference = url.searchParams.get('reference') || url.searchParams.get('tx_ref'); const transactionId = url.searchParams.get('transaction_id'); const payment = await verifyPayment(provider, reference, transactionId); return res.writeHead(302, { location: `${appUrl}/#payment-success?code=${encodeURIComponent(payment.accessCode)}&plan=${encodeURIComponent(payment.plan)}` }).end();
    }
    return send(res, 404, { error: 'Not found' });
  } catch (error) { return send(res, 400, { error: error.message }); }
}

createServer(handle).listen(port, () => {
  console.log(`Payment backend listening on http://localhost:${port}`);
  if (missingConfig.length) console.warn(`Missing configuration: ${missingConfig.join(', ')}`);
  else console.log('Paystack and Flutterwave configuration loaded.');
});
