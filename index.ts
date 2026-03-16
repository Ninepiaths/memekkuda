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
  windowMs: 60_000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(limiter);

app.use(express.static(path.join(process.cwd(), 'public')));

app.use((req: Request, _res: Response, next: NextFunction) => {
  const clientIp =
    (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
    req.headers['x-real-ip'] ||
    req.socket.remoteAddress ||
    'unknown';

  console.log(`[REQ] ${req.method} ${req.path} → ${clientIp}`);
  next();
});

app.get('/', (_req: Request, res: Response) => {
  res.send('Growtopia GTPS Backend Running');
});

/*
LOGIN DASHBOARD
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
LOGIN VALIDATE
*/
app.all('/player/growid/login/validate', async (req: Request, res: Response) => {
  try {
    const formData = req.body as Record<string, string>;

    const _token = formData._token;
    const growId = formData.growId;
    const password = formData.password;
    const email = formData.email;

    let token = '';

    if (email) {
      token = Buffer.from(
        `_token=${_token}&growId=${growId}&password=${password}&email=${email}`
      ).toString('base64');
    } else {
      token = Buffer.from(
        `_token=${_token}&growId=${growId}&password=${password}`
      ).toString('base64');
    }

    res.setHeader("Content-Type", "text/plain");

    res.send(
`status|success
message|Account Validated
token|${token}
url|
accountType|growtopia`
    );

  } catch (error) {
    console.log(`[ERROR]: ${error}`);

    res.setHeader("Content-Type", "text/plain");

    res.send(
`status|error
message|Server Error`
    );
  }
});

/*
CHECK TOKEN REDIRECT
*/
app.all('/player/growid/checktoken', async (_req: Request, res: Response) => {
  return res.redirect(307, '/player/growid/validate/checktoken');
});

/*
VALIDATE CHECKTOKEN (RELOG)
*/
app.all('/player/growid/validate/checktoken', async (req: Request, res: Response) => {
  try {

    let refreshToken: string | undefined;
    let clientData: string | undefined;

    const formData = req.body as Record<string, string>;

    if (formData.refreshToken) refreshToken = formData.refreshToken;
    if (formData.clientData) clientData = formData.clientData;

    if (!refreshToken || !clientData) {

      const raw = Object.keys(formData)[0];

      if (raw) {
        const params = new URLSearchParams(raw);

        refreshToken = params.get("refreshToken") || undefined;
        clientData = params.get("clientData") || undefined;
      }

    }

    if (!refreshToken || !clientData) {

      res.setHeader("Content-Type", "text/plain");

      return res.send(
`status|error
message|invalid token`
      );

    }

    let decodedRefreshToken = Buffer.from(refreshToken, 'base64').toString('utf-8');

    decodedRefreshToken = decodedRefreshToken
      .replace('&reg=0', '')
      .replace('&reg=1', '');

    const newToken = Buffer.from(
      decodedRefreshToken.replace(
        /(_token=)[^&]*/,
        `$1${Buffer.from(clientData).toString('base64')}`
      )
    ).toString('base64');

    res.setHeader("Content-Type", "text/plain");

    res.send(
`status|success
message|Account Validated
token|${newToken}
url|
accountType|growtopia
accountAge|1`
    );

  } catch (error) {

    console.log(`[ERROR]: ${error}`);

    res.setHeader("Content-Type", "text/plain");

    res.send(
`status|error
message|server error`
    );

  }
});

app.listen(PORT, () => {
  console.log(`[SERVER] Running on http://localhost:${PORT}`);
});

export default app;
