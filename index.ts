import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import path from 'path';
import fs from 'fs';

const app = express();
const PORT = 3000;

app.set('trust proxy', 1);

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cors({
  origin: '*',
  credentials: true
}));

// Rate limiter
const limiter = rateLimit({
  windowMs: 60_000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

app.use(express.static(path.join(process.cwd(), 'public')));

// Request logging
app.use((req: Request, res: Response, next: NextFunction) => {
  const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
  console.log(`[REQ] ${req.method} ${req.path} → ${clientIp}`);
  next();
});

app.get('/', (_req: Request, res: Response) => {
  res.send('Growtopia Login Server OK');
});

/**
 * @fix VALIDATE LOGIN - Format token GROWTOPIA CORRECT
 */
app.all('/player/growid/login/validate', async (req: Request, res: Response) => {
  try {
    const formData = req.body as Record<string, string>;
    
    const _token = formData._token || '';
    const growId = formData.growId || '';
    const password = formData.password || '';
    const email = formData.email || '';

    // ✅ FIX: Build token dengan format GROWTOPIA yang benar
    const tokenPayload = `_token=${_token}&growId=${growId}&password=${password}`;
    const token = Buffer.from(tokenPayload).toString('base64');

    console.log(`[VALIDATE] Login: ${growId}, Token: ${token.substring(0, 20)}...`);

    res.json({
      status: 'success',
      message: 'Account Validated.',
      token: token,
      url: '',
      accountType: 'growtopia'
    });
  } catch (error) {
    console.error(`[VALIDATE ERROR]:`, error);
    res.status(200).json({ // Growtopia expect 200 even on error
      status: 'error',
      message: 'Validation failed'
    });
  }
});

/**
 * @fix CHECKTOKEN - Proper token regeneration untuk Growtopia
 */
app.all('/player/growid/checktoken', async (req: Request, res: Response) => {
  // ✅ FIX: Direct handle, no redirect
  handleCheckToken(req, res);
});

/**
 * @fix DASHBOARD - Encode clientData properly
 */
app.all('/player/login/dashboard', async (req: Request, res: Response) => {
  try {
    let clientData = '';
    
    // Handle different body formats
    if (req.body && typeof req.body === 'object') {
      const bodyKeys = Object.keys(req.body);
      if (bodyKeys.length > 0) {
        clientData = bodyKeys[0]; // First key contains data
      }
    }

    // ✅ FIX: Proper base64 encoding tanpa extra quotes
    const encodedClientData = Buffer.from(clientData || '').toString('base64');

    const templatePath = path.join(process.cwd(), 'template', 'dashboard.html');
    let templateContent = fs.readFileSync(templatePath, 'utf-8');
    
    const htmlContent = templateContent.replace('{{ data }}', encodedClientData);
    
    res.set({
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache'
    });
    res.send(htmlContent);
  } catch (error) {
    console.error('[DASHBOARD ERROR]:', error);
    res.status(500).send('Dashboard error');
  }
});

/**
 * @fix CORE: Proper checktoken handler untuk Growtopia
 */
async function handleCheckToken(req: Request, res: Response) {
  try {
    let refreshToken: string = '';
    let clientData: string = '';

    // Parse request body - handle all formats
    if (req.body && typeof req.body === 'object') {
      const formData = req.body as Record<string, string>;
      
      // Method 1: Direct properties
      if (formData.refreshToken) refreshToken = formData.refreshToken;
      if (formData.clientData) clientData = formData.clientData;
      
      // Method 2: Single key payload (Growtopia style)
      if (!refreshToken && Object.keys(formData).length === 1) {
        const rawPayload = Object.keys(formData)[0];
        const params = new URLSearchParams(rawPayload);
        refreshToken = params.get('refreshToken') || '';
        clientData = params.get('clientData') || '';
      }
    }

    console.log(`[CHECKTOKEN] refreshToken: ${refreshToken ? 'OK' : 'MISSING'}, clientData: ${clientData ? 'OK' : 'MISSING'}`);

    if (!refreshToken) {
      return res.status(200).json({
        status: 'error',
        message: 'Invalid refresh token'
      });
    }

    // ✅ FIX: Decode dan regenerate token dengan format GROWTOPIA
    let decodedToken = Buffer.from(refreshToken, 'base64').toString('utf-8');
    
    // Clean reg parameter
    decodedToken = decodedToken.replace(/&reg=\d+/, '');
    
    // ✅ FIX: Replace _token dengan clientData (required by Growtopia)
    if (clientData) {
      const newTokenPayload = decodedToken.replace(
        /(_token=)[^&]*/, 
        `$1${Buffer.from(clientData).toString('base64')}`
      );
      decodedToken = newTokenPayload;
    }

    // Final token untuk Growtopia
    const finalToken = Buffer.from(decodedToken).toString('base64');

    console.log(`[CHECKTOKEN] New token generated`);

    res.json({
      status: 'success',
      message: 'Token refreshed',
      token: finalToken,
      url: '',
      accountType: 'growtopia',
      accountAge: 2, // Required by some clients
      rl: true // Rate limit status
    });

  } catch (error) {
    console.error('[CHECKTOKEN ERROR]:', error);
    res.status(200).json({
      status: 'error',
      message: 'Token refresh failed'
    });
  }
}

// Error handler
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error('[GLOBAL ERROR]:', err);
  res.status(200).json({ status: 'error', message: 'Server error' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Growtopia Login Server running on http://localhost:${PORT}`);
  console.log(`📱 Test endpoints:`);
  console.log(`   GET  /`);
  console.log(`   POST /player/growid/login/validate`);
  console.log(`   POST /player/growid/checktoken`);
});

export default app;
