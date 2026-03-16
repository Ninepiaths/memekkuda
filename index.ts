import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";
import path from "path";
import fs from "fs";

const app = express();
const PORT = 3000;

/* CONFIG */
const SERVER_IP = "secret.rizqn.my.id"; // ganti dengan ip / domain server
const SERVER_PORT = "17091";

app.set("trust proxy", 1);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

const limiter = rateLimit({
  windowMs: 60000,
  max: 100,
});

app.use(limiter);

/* LOG REQUEST */
app.use((req: Request, _res: Response, next: NextFunction) => {
  const ip =
    (req.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim() ||
    req.socket.remoteAddress ||
    "unknown";

  console.log(`[REQ] ${req.method} ${req.path} → ${ip}`);
  next();
});

/* ROOT */
app.get("/", (_req: Request, res: Response) => {
  res.send("GTPS Backend Running");
});

/*
LOGIN DASHBOARD
*/
app.all("/player/login/dashboard", async (req: Request, res: Response) => {
  let clientData = "";

  if (req.body && Object.keys(req.body).length > 0) {
    clientData = Object.keys(req.body)[0];
  }

  const encoded = Buffer.from(clientData).toString("base64");

  const template = fs.readFileSync(
    path.join(process.cwd(), "template", "dashboard.html"),
    "utf-8"
  );

  const html = template.replace("{{ data }}", encoded);

  res.setHeader("Content-Type", "text/html");
  res.send(html);
});

/*
LOGIN VALIDATE
*/
app.all("/player/growid/login/validate", async (req: Request, res: Response) => {
  try {
    const form = req.body as Record<string, string>;

    const _token = form._token || "";
    const growId = form.growId || "";
    const password = form.password || "";
    const email = form.email || "";

    let token = "";

    if (email !== "") {
      token = Buffer.from(
        `_token=${_token}&growId=${growId}&password=${password}&email=${email}`
      ).toString("base64");
    } else {
      token = Buffer.from(
        `_token=${_token}&growId=${growId}&password=${password}`
      ).toString("base64");
    }

    res.setHeader("Content-Type", "text/plain");

    res.send(
`status|success
message|Account Validated
token|${token}
server|${SERVER_IP}
port|${SERVER_PORT}
type|1
accountType|growtopia`
    );
  } catch (err) {
    console.log(err);

    res.setHeader("Content-Type", "text/plain");

    res.send(
`status|error
message|server error`
    );
  }
});

/*
CHECKTOKEN REDIRECT
*/
app.all("/player/growid/checktoken", async (_req: Request, res: Response) => {
  res.redirect(307, "/player/growid/validate/checktoken");
});

/*
CHECKTOKEN VALIDATION (RELOG)
*/
app.all("/player/growid/validate/checktoken", async (req: Request, res: Response) => {
  try {
    let refreshToken: string | undefined;
    let clientData: string | undefined;

    const body = req.body as Record<string, string>;

    if (body.refreshToken) refreshToken = body.refreshToken;
    if (body.clientData) clientData = body.clientData;

    if (!refreshToken || !clientData) {
      const raw = Object.keys(body)[0];

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

    let decoded = Buffer.from(refreshToken, "base64").toString("utf-8");

    decoded = decoded.replace("&reg=0", "").replace("&reg=1", "");

    const newToken = Buffer.from(
      decoded.replace(
        /(_token=)[^&]*/,
        `$1${Buffer.from(clientData).toString("base64")}`
      )
    ).toString("base64");

    res.setHeader("Content-Type", "text/plain");

    res.send(
`status|success
message|Account Validated
token|${newToken}
server|${SERVER_IP}
port|${SERVER_PORT}
type|1
accountType|growtopia
accountAge|1`
    );
  } catch (err) {
    console.log(err);

    res.setHeader("Content-Type", "text/plain");

    res.send(
`status|error
message|server error`
    );
  }
});

/* START SERVER */
app.listen(PORT, () => {
  console.log(`Backend running on http://localhost:${PORT}`);
});
