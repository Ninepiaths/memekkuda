import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import path from 'path';
import fs from 'fs';

const app = express();
const PORT = 3000;

app.set('trust proxy', 1);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

const limiter = rateLimit({
  windowMs: 60000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

app.use(express.static(path.join(process.cwd(), 'public')));

app.use((req: Request, res: Response, next: NextFunction) => {
  const clientIp =
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    req.headers['x-real-ip'] ||
    req.socket.remoteAddress ||
    'unknown';

  console.log(`[REQ] ${req.method} ${req.path} → ${clientIp}`);
  next();
});

app.get('/', (_req: Request, res: Response) => {
  res.send('GTPS Login Backend Running');
});

/*
Dashboard login page
*/
app.all('/player/login/dashboard', async (req: Request, res: Response) => {
  const body = req.body;
  let clientData = '';

  if (body && typeof body === 'object' && Object.keys(body).length > 0) {
    clientData = Object.keys(body)[0];
  }

  const encodedClientData = Buffer.from(clientData).toString('base64');

  const templatePath = path.join(process.cwd(), 'template', 'dashboard.html');
  const templateContent = fs.readFileSync(templatePath, 'utf-8');

  const htmlContent = templateContent.replace('{{ data }}', encodedClientData);

  res.setHeader('Content-Type', 'text/html');
  res.send(htmlContent);
});

/*
Login validate
*/
app.all('/player/growid/register/validate', async (req: Request, res: Response) => {
  try {

    const formData = req.body as Record<string, string>;

    const growId = formData.growId;
    const password = formData.password;

    if (!growId || !password) {
      return res.json({
        status: 'error',
        message: 'Missing GrowID or password'
      });
    }

    const token = Buffer.from(
      `growId=${growId}&password=${password}`
    ).toString('base64');

    console.log(`[REGISTER] ${growId}`);

    res.json({
      status: 'success',
      message: 'Account Created.',
      token,
      url: '',
      accountType: 'growtopia'
    });

  } catch (error) {

    console.log(`[REGISTER ERROR]: ${error}`);

    res.json({
      status: 'error',
      message: 'Internal Server Error'
    });

  }
});

/*
Check token redirect
*/
app.all('/player/growid/checktoken', async (_req: Request, res: Response) => {
  return res.redirect(307, '/player/growid/validate/checktoken');
});

/*
Check token validate
*/
app.all('/player/growid/validate/checktoken', async (req: Request, res: Response) => {
  try {

    const formData = req.body as Record<string, string>;

    const refreshToken = formData.refreshToken;
    const clientData = formData.clientData;

    if (!refreshToken || !clientData) {
      return res.json({
        status: 'error',
        message: 'Missing refreshToken or clientData'
      });
    }

    let decodedRefreshToken = Buffer.from(refreshToken, 'base64').toString('utf-8');

    const token = Buffer.from(decodedRefreshToken).toString('base64');

    res.json({
      status: 'success',
      message: 'Account Validated.',
      token,
      url: '',
      accountType: 'growtopia',
      accountAge: 2
    });

  } catch (error) {
    console.log(`[ERROR]: ${error}`);

    res.json({
      status: 'error',
      message: 'Internal Server Error'
    });
  }
});

app.listen(PORT, () => {
  console.log(`[SERVER] Running on http://localhost:${PORT}`);
});

export default app;
