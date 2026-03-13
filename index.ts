import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import path from 'path';
import fs from 'fs';

const app = express();
const PORT = 3000; // ubah sesuai kebutuhan, misal 443 kalau pakai HTTPS nanti

// Trust proxy jika pakai reverse proxy (Cloudflare, nginx, dll)
app.set('trust proxy', 1);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({
  origin: '*', // ubah ke domain spesifik kalau production
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limiting lebih ketat untuk endpoint sensitif
const authLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 menit
  max: 15,             // max 15 request per menit per IP
  message: { status: 'error', message: 'Too many requests, try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
});

// Apply rate limit
app.use('/player/growid/', authLimiter);
app.use(generalLimiter);

// Serve static files (dashboard, assets, dll)
app.use(express.static(path.join(process.cwd(), 'public')));

// Logging request (untuk debug & security)
app.use((req: Request, res: Response, next: NextFunction) => {
  const clientIp = 
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    req.headers['x-real-ip'] as string ||
    req.socket.remoteAddress ||
    'unknown';

  console.log(
    `[${new Date().toISOString()}] ${req.method} ${req.path} | IP: ${clientIp} | Status: ${res.statusCode}`
  );
  next();
});

// Root (untuk tes server hidup)
app.get('/', (_req: Request, res: Response) => {
  res.send('GTPS Login Backend - OK');
});

// Dashboard login page
app.all('/player/login/dashboard', (req: Request, res: Response) => {
  try {
    let clientData = '';

    // Format body yang sering dipakai Growtopia client (single key dengan \n separator)
    if (req.body && typeof req.body === 'object' && Object.keys(req.body).length > 0) {
      const firstKey = Object.keys(req.body)[0];
      if (typeof req.body[firstKey] === 'string') {
        clientData = firstKey; // biasanya key-nya adalah data itu sendiri
      }
    }

    // Encode client data ke base64 (untuk _token di form)
    const encodedClientData = Buffer.from(clientData || '').toString('base64');

    // Baca template HTML
    const templatePath = path.join(process.cwd(), 'template', 'dashboard.html');
    if (!fs.existsSync(templatePath)) {
      return res.status(500).send('Template not found');
    }

    const templateContent = fs.readFileSync(templatePath, 'utf-8');
    const html = templateContent.replace('<%= data %>', encodedClientData);

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch (err) {
    console.error('[DASHBOARD ERROR]', err);
    res.status(500).send('Server error');
  }
});

// Endpoint validasi login pertama (dari form HTML)
app.all('/player/growid/login/validate', authLimiter, (req: Request, res: Response) => {
  try {
    const formData = req.body as Record<string, string>;

    const _token   = formData._token   || '';
    const growId   = (formData.growId  || '').trim();
    const password = formData.password || '';

    if (!growId || !password) {
      return res.status(200).json({
        status: 'error',
        message: 'GrowID and password are required'
      });
    }

    // Di sini bisa tambah validasi ke database nanti
    // Contoh:
    // const user = await db.findUser(growId.toLowerCase());
    // if (!user || !await verifyPassword(password, user.hash)) { return error }

    // Format ltoken yang akan dikirim ke client Growtopia
    const reg = '0'; // ubah ke '1' kalau support register
    const payload = `_token=${_token}&growId=${encodeURIComponent(growId)}&password=${encodeURIComponent(password)}&reg=${reg}`;

    const token = Buffer.from(payload).toString('base64');

    res.json({
      status: 'success',
      message: 'Account Validated.',
      token,                    // ini yang akan dikirim sebagai ltoken ke client
      url: '',
      accountType: 'growtopia',
      accountAge: 420,          // dummy, client pakai untuk tampilan
    });
  } catch (err) {
    console.error('[VALIDATE ERROR]', err);
    res.status(200).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// Redirect checktoken (beberapa client memanggil ini dulu)
app.all('/player/growid/checktoken', (_req: Request, res: Response) => {
  res.redirect(307, '/player/growid/validate/checktoken');
});

// Refresh/validate token (client mengirim refreshToken + clientData baru)
app.all('/player/growid/validate/checktoken', authLimiter, async (req: Request, res: Response) => {
  try {
    let refreshToken = '';
    let clientData = '';

    // Handle berbagai format body yang dikirim client Growtopia
    if (req.body && typeof req.body === 'object') {
      const body = req.body as Record<string, any>;

      if (body.refreshToken && body.clientData) {
        refreshToken = body.refreshToken;
        clientData = body.clientData;
      }
      // Format single-key (Growtopia sering pakai ini)
      else if (Object.keys(body).length === 1) {
        const raw = Object.keys(body)[0] as string;
        const params = new URLSearchParams(raw);
        refreshToken = params.get('refreshToken') || '';
        clientData = params.get('clientData') || '';
      }
    }

    // Fallback baca raw body jika masih kosong
    if (!refreshToken || !clientData) {
      const rawBody = await new Promise<string>((resolve) => {
        let data = '';
        req.on('data', (chunk) => (data += chunk));
        req.on('end', () => resolve(data));
      });

      if (rawBody) {
        const params = new URLSearchParams(rawBody);
        refreshToken = params.get('refreshToken') || refreshToken;
        clientData = params.get('clientData') || clientData;
      }
    }

    if (!refreshToken || !clientData) {
      return res.status(200).json({
        status: 'error',
        message: 'Missing refreshToken or clientData'
      });
    }

    // Decode refresh token lama
    let decoded = Buffer.from(refreshToken, 'base64').toString('utf-8');

    // Ganti _token dengan clientData terbaru (yang paling fresh)
    const newClientToken = Buffer.from(clientData).toString('base64');
    decoded = decoded.replace(/(_token=)[^&]*/, `$1${newClientToken}`);

    // Hapus &reg= kalau ada (beberapa client sensitif)
    decoded = decoded.replace(/&reg=[01]/g, '');

    // Buat token baru
    const newToken = Buffer.from(decoded).toString('base64');

    res.json({
      status: 'success',
      message: 'Account Validated.',
      token: newToken,
      url: '',
      accountType: 'growtopia',
      accountAge: 420,
    });
  } catch (err) {
    console.error('[CHECKTOKEN ERROR]', err);
    res.status(200).json({
      status: 'error',
      message: 'Internal server error'
    });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`[GTPS Login Backend] Running on http://localhost:${PORT}`);
  console.log(`Dashboard: http://localhost:${PORT}/player/login/dashboard`);
});

export default app;
