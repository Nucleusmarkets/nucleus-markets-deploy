// server/index.ts
import express from "express";
import helmet from "helmet";
import compression from "compression";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
var here = path.dirname(fileURLToPath(import.meta.url));
var publicDir = path.join(here, "public");
var app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:", "blob:"],
        mediaSrc: ["'self'", "blob:"],
        connectSrc: ["'self'"],
        frameAncestors: ["'none'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"]
      }
    },
    crossOriginEmbedderPolicy: false
  })
);
app.use(compression());
app.use(express.json({ limit: "100kb" }));
app.get("/api/health", (_req, res) => {
  res.json({ ok: true, service: "nucleus-markets", time: (/* @__PURE__ */ new Date()).toISOString() });
});
app.post(["/api/auth/register", "/api/auth/login"], (_req, res) => {
  res.status(503).json({
    ok: false,
    message: "Account opening goes live shortly. We'll be ready for you very soon."
  });
});
app.use("/api", (_req, res) => res.status(404).json({ ok: false, message: "Not found" }));
if (fs.existsSync(publicDir)) {
  app.use(
    "/assets",
    express.static(path.join(publicDir, "assets"), { immutable: true, maxAge: "1y" })
  );
  app.use(express.static(publicDir, { maxAge: "1h", index: false }));
  app.get("*", (_req, res) => {
    res.setHeader("Cache-Control", "no-cache");
    res.sendFile(path.join(publicDir, "index.html"));
  });
}
var port = Number(process.env.PORT) || 5e3;
app.listen(port, "0.0.0.0", () => {
  console.log(`nucleus-markets listening on :${port}`);
});
