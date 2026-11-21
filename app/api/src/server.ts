// Minimal notes API for the lab. Deliberately tiny: the project is about the
// cluster configuration around the app, not the app itself.
import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { Pool } from "pg";

const PORT = Number(process.env.PORT ?? 3000);
const MAX_BODY_BYTES = 10 * 1024;

// pg reads PGHOST / PGUSER / PGPASSWORD / PGDATABASE from the environment,
// so connection settings live in the Kubernetes manifests, not in code.
//
// PGPASSWORD_FILE (scenario 4): read the password from a mounted Secret file
// instead of an environment variable. An env var is copied into every child
// process, /proc/<pid>/environ and crash dumps; a file has to be read on
// purpose. The file is read for every new connection, so a rotated Secret is
// picked up without a restart (an env var is fixed for the process lifetime).
const passwordFile = process.env.PGPASSWORD_FILE;
const pool = new Pool({
  max: 5,
  connectionTimeoutMillis: 3000,
  ...(passwordFile
    ? { password: () => readFileSync(passwordFile, "utf8").replace(/\n$/, "") }
    : {}),
});

let schemaReady = false;

async function ensureSchema(): Promise<void> {
  // The database may start after the API. Retry instead of crashing, and let
  // the readiness probe keep traffic away until this succeeds.
  for (;;) {
    try {
      await pool.query(
        `CREATE TABLE IF NOT EXISTS notes (
           id         SERIAL PRIMARY KEY,
           text       TEXT NOT NULL,
           created_at TIMESTAMPTZ NOT NULL DEFAULT now()
         )`,
      );
      schemaReady = true;
      console.log("schema ready");
      return;
    } catch (err) {
      console.error("database not ready, retrying in 2s:", (err as Error).message);
      await new Promise((resolve) => setTimeout(resolve, 2000));
    }
  }
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    // Cap the body size so one request cannot exhaust the process memory.
    if (size > MAX_BODY_BYTES) throw new Error("body too large");
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const path = new URL(req.url ?? "/", "http://localhost").pathname;

  // Liveness: "is the process alive?" - must NOT depend on the database,
  // otherwise a DB outage makes Kubernetes restart healthy API pods.
  if (req.method === "GET" && path === "/healthz") {
    return sendJson(res, 200, { status: "ok" });
  }

  // Readiness: "can this pod serve traffic right now?" - does check the DB.
  if (req.method === "GET" && path === "/readyz") {
    if (!schemaReady) return sendJson(res, 503, { status: "starting" });
    try {
      await pool.query("SELECT 1");
      return sendJson(res, 200, { status: "ready" });
    } catch {
      return sendJson(res, 503, { status: "database unavailable" });
    }
  }

  if (req.method === "GET" && path === "/api/notes") {
    const result = await pool.query(
      "SELECT id, text, created_at FROM notes ORDER BY id DESC LIMIT 50",
    );
    return sendJson(res, 200, result.rows);
  }

  if (req.method === "POST" && path === "/api/notes") {
    let text: unknown;
    try {
      text = (JSON.parse(await readBody(req)) as { text?: unknown }).text;
    } catch {
      return sendJson(res, 400, { error: "invalid JSON body" });
    }
    if (typeof text !== "string" || text.length === 0 || text.length > 500) {
      return sendJson(res, 400, { error: "text must be a string of 1-500 chars" });
    }
    // Parameterized query ($1): user input never becomes part of the SQL text.
    const result = await pool.query(
      "INSERT INTO notes (text) VALUES ($1) RETURNING id, text, created_at",
      [text],
    );
    return sendJson(res, 201, result.rows[0]);
  }

  sendJson(res, 404, { error: "not found" });
}

const server = createServer((req, res) => {
  handle(req, res).catch((err: Error) => {
    console.error("request failed:", err.message);
    if (!res.headersSent) sendJson(res, 500, { error: "internal error" });
  });
});

server.listen(PORT, () => console.log(`api listening on :${PORT}`));
void ensureSchema();

// Kubernetes sends SIGTERM before killing a pod. Finish in-flight requests
// and close DB connections instead of dropping them.
process.on("SIGTERM", () => {
  console.log("SIGTERM received, shutting down");
  server.close(() => {
    void pool.end().then(() => process.exit(0));
  });
});
