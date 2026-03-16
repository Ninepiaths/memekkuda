import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import rateLimit from "express-rate-limit";
import path from "path";
import fs from "fs";

const app = express();
const PORT = 3000;

app.set("trust proxy", 1);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300,
});

app.use(limiter);

app.use(express.static(path.join(process.cwd(), "public")));

app.use((req: Request, res: Response, next: NextFunction) => {
  const ip =
    (req.headers["x-forwarded-for"] as string)?.split(",")[0] ||
    req.socket.remoteAddress ||
    "unknown";

  console.log(`[REQ] ${req.method} ${req.path} → ${ip}`);
  next();
});

app.get("/", (_req: Request, res: Response) => {
  res.send("Backend Running");
});

app.all("/player/login/dashboard", (req: Request, res: Response) => {
  let clientData = "";

  if (req.body && typeof req.body === "object") {
    clientData = Object.keys(req.body)[0] || "";
  }

  const encoded = Buffer.from(clientData).toString("base64");

  const templatePath = path.join(process.cwd(), "template", "dashboard.html");

  let html = fs.readFileSync(templatePath, "utf8");

  html = html.replace("{{ data }}", encoded);

  res.setHeader("Content-Type", "text/html");
  res.send(html);
});

app.post("/player/growid/login/validate", (req: Request, res: Response) => {
  try {
    const { _token, growId, password, email } = req.body;

    let payload = `_token=${_token}&growId=${growId}&password=${password}`;

    if (email) {
      payload += `&email=${email}`;
    }

    const token = Buffer.from(payload).toString("base64");

    res.json({
      status: "success",
      message: "Account Validated",
      token,
      url: "",
      accountType: "growtopia",
    });
  } catch (err) {
    console.log(err);

    res.json({
      status: "error",
      message: "Internal Server Error",
    });
  }
});

function parseBody(req: Request) {
  let refreshToken: string | undefined;
  let clientData: string | undefined;

  if (typeof req.body === "object") {
    const body = req.body as Record<string, string>;

    if (body.refreshToken) refreshToken = body.refreshToken;
    if (body.clientData) clientData = body.clientData;

    if (!refreshToken && Object.keys(body).length === 1) {
      const raw = Object.keys(body)[0];
      const params = new URLSearchParams(raw);

      refreshToken = params.get("refreshToken") || undefined;
      clientData = params.get("clientData") || undefined;
    }
  }

  return { refreshToken, clientData };
}

app.all("/player/growid/checktoken", (req: Request, res: Response) => {
  handleCheckToken(req, res);
});

app.all("/player/growid/validate/checktoken", (req: Request, res: Response) => {
  handleCheckToken(req, res);
});

function handleCheckToken(req: Request, res: Response) {
  try {
    const { refreshToken, clientData } = parseBody(req);

    if (!refreshToken || !clientData) {
      return res.json({
        status: "error",
        message: "Missing refreshToken or clientData",
      });
    }

    let decoded = Buffer.from(refreshToken, "base64").toString();

    decoded = decoded.replace("&reg=0", "").replace("&reg=1", "");

    const params = new URLSearchParams(decoded);

    params.set("_token", Buffer.from(clientData).toString("base64"));

    const token = Buffer.from(params.toString()).toString("base64");

    res.json({
      status: "success",
      message: "Account Validated",
      token,
      url: "",
      accountType: "growtopia",
      accountAge: 1,
    });
  } catch (err) {
    console.log(err);

    res.json({
      status: "error",
      message: "Token Error",
    });
  }
}

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
