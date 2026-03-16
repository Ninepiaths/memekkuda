import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import path from 'path';
import fs from 'fs';

const app = express();
const PORT = 3000;

// v5.37 SPECIFIC: Trust proxy & body limits
app.set('trust proxy', 1);
app.enable('trust proxy');

app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// v5.37: Higher limits untuk modded client
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ 
  extended: true, 
  limit: '50mb',
  parameterLimit: 100000 
}));

// v5.37 Rate limit - exact spec
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 200, // v5.37 expect higher
  message: { status: 'error', message: 'Rate limited' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path.includes('checktoken') // Skip rate limit untuk token refresh
});
app.use(limiter);

// Static files
app.use(express.static(path.join(process.cwd(), 'public'), {
  setHeaders: (res) => {
    res.set('Cache-Control', 'public, max-age=3600');
  }
}));

// v5.37 Request logger
app.use((req: Request, res: Response, next: NextFunction) => {
  const ip = req.ip || req.get('X-Forwarded-For')?.split(',')[0]?.trim() || 'unknown';
  console.log(`[v5.37] ${new Date().toISOString()} ${req.method} ${req.path} [${ip}]`);
  next();
});

// v5.37 ROOT - exact response
app.get('/', (req: Request, res: Response) => {
  res.json({ 
    status: 'ok', 
    version: 'v5.37-compatible',
    endpoints: ['/player/growid/login/validate', '/player/growid/checktoken']
  });
});

/**
 * 🎯 v5.37 VALIDATE LOGIN - EXACT FORMAT
 */
app.all('/player/growid/login/validate', async (req: Request, res: Response) => {
  try {
    console.log('[v5.37 VALIDATE] Request body:', req.body);
    
    const body = req.body as any;
    let _token = '';
    let growId = '';
    let password = '';
    
    // v5.37 handles multiple body formats
    if (typeof body === 'object') {
      if (body._token) _token = body._token;
      if (body.growId) growId = body.growId;
      if (body.password) password = body.password;
      
      // Single key payload (Growtopia style)
      if (Object.keys(body).length === 1) {
        const raw = Object.keys(body)[0];
        const params = new URLSearchParams(raw);
        _token = params.get('_token') || '';
        growId = params.get('growId') || '';
        password = params.get('password') || '';
      }
    }

    if (!growId || !password) {
      return res.status(200).json({
        status: 'error',
        message: 'Invalid credentials',
        rl: false
      });
    }

    // ✅ v5.37 EXACT TOKEN FORMAT
    const tokenPayload = `_token=${_token}&growId=${encodeURIComponent(growId)}&password=${encodeURIComponent(password)}&rt=0`;
    const token = Buffer.from(tokenPayload, 'utf8').toString('base64');

    console.log(`[v5.37 LOGIN] ${growId} → Token OK`);

    // v5.37 EXACT RESPONSE
    res.status(200).json({
      status: 'success',
      message: 'Account Validated.',
      token: token,
      url: '',
      accountType: 'growtopia',
      rl: true,        // Rate limit status
      accountAge: 365, // Days
      reg: 1           // Registered status
    });

  } catch (error) {
    console.error('[v5.37 VALIDATE ERROR]:', error);
    res.status(200).json({
      status: 'error',
      message: 'Server error',
      rl: true
    });
  }
});

/**
 * 🎯 v5.37 CHECKTOKEN - Multiple calls handling
 */
app.all('/player/growid/checktoken', async (req: Request, res: Response) => {
  try {
    console.log('[v5.37 CHECKTOKEN] Body:', req.body);
    
    let refreshToken = '';
    let clientData = '';
    
    const body = req.body as any;
    
    // Parse v5.37 token formats
    if (typeof body === 'object') {
      refreshToken = body.refreshToken || '';
      clientData = body.clientData || '';
      
      // Single key format
      if (Object.keys(body).length === 1 && !refreshToken) {
        const raw = Object.keys(body)[0];
        const params = new URLSearchParams(raw);
        refreshToken = params.get('refreshToken') || '';
        clientData = params.get('clientData') || '';
      }
    }

    if (!refreshToken) {
      return res.status(200).json({
        status: 'error',
        message: 'Invalid refresh token',
        rl: true
      });
    }

    // ✅ v5.37 Token refresh logic
    let decoded = Buffer.from(refreshToken, 'base64').toString('utf8');
    
    // Clean & update token
    decoded = decoded.replace(/&rt=\d+/, '');
    if (clientData) {
      // Update _token with clientData
      const clientToken = Buffer.from(clientData, 'utf8').toString('base64');
      decoded = decoded.replace(/(_token=)[^&]+/, `$1${clientToken}`);
    }
    
    // Add v5.37 required params
    decoded += '&rt=1&rlm=1';
    const newToken = Buffer.from(decoded, 'utf8').toString('base64');

    console.log('[v5.37 CHECKTOKEN] Token refreshed');

    // v5.37 EXACT RESPONSE
    res.status(200).json({
      status: 'success',
      message: 'Token refreshed successfully',
      token: newToken,
      url: '',
      accountType: 'growtopia',
      rl: true,
      accountAge: 365,
      reg: 1
    });

  } catch (error) {
    console.error('[v5.37 CHECKTOKEN ERROR]:', error);
    res.status(200).json({
      status: 'error',
      message: 'Token refresh failed',
      rl: true
    });
  }
});

/**
 * v5.37 DASHBOARD - Untuk web login
 */
app.all('/player/login/dashboard', async (req: Request, res: Response) => {
  try {
    let clientData = '';
    const body = req.body as any;
    
    if (body && Object.keys(body).length > 0) {
      clientData = Object.keys(body)[0];
    }
    
    const encodedData = Buffer.from(clientData || '', 'utf8').toString('base64');
    
    const templatePath = path.join(process.cwd(), 'template', 'dashboard.html');
    let html = fs.readFileSync(templatePath, 'utf8');
    html = html.replace('{{ data }}', encodedData);
    
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
    
  } catch (error) {
    console.error('[DASHBOARD ERROR]:', error);
    res.status(500).send(`
      <!DOCTYPE html>
      <html>
      <body>
        <h1>Growtopia v5.37 Login Dashboard</h1>
        <p>Server ready! Check console for errors.</p>
      </body>
      </html>
    `);
  }
});

// v5.37 Error handler - ALWAYS 200 status
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  console.error('[v5.37 ERROR]:', err);
  res.status(200).json({
    status: 'error',
    message: 'Internal server error',
    rl: true
  });
});

// 404 handler
app.use('*', (req: Request, res: Response) => {
  res.status(200).json({
    status: 'error',
    message: 'Endpoint not found',
    rl: true
  });
});

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log('\n🚀 === GROWTOPIA v5.37 LOGIN SERVER ===');
  console.log(`📡 Running on: http://localhost:${PORT}`);
  console.log(`🌐 All interfaces: http://0.0.0.0:${PORT}`);
  console.log('✅ Ready for modded APK clients!\n');
});

export default app;
