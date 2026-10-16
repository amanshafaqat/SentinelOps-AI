import express from 'express';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import http from 'http';
import { spawn, execSync, ChildProcess } from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const BACKEND_PORT = 8001;

let backendProcess: ChildProcess | null = null;
let isShuttingDown = false;
let isBackendHealthy = false;

/**
 * Ensures a working Python environment with all SentinelOps AI backend dependencies.
 */
function ensurePythonEnvironment(): string {
  const venvDir = path.join(__dirname, '.venv');
  const venvPython = path.join(venvDir, 'bin', 'python');
  const venvUvicorn = path.join(venvDir, 'bin', 'uvicorn');

  // 1. Check if persistent .venv already has working uvicorn
  if (fs.existsSync(venvUvicorn)) {
    try {
      execSync(`"${venvPython}" -c "import uvicorn, fastapi, sqlalchemy"`, { stdio: 'ignore' });
      return venvPython;
    } catch {
      console.warn('[server.ts] Existing .venv incomplete. Re-initializing...');
    }
  }

  // 2. Check if global python3 has uvicorn
  try {
    execSync('python3 -c "import uvicorn, fastapi, sqlalchemy"', { stdio: 'ignore' });
    console.log('[server.ts] Using system python3 with pre-installed backend packages.');
    return 'python3';
  } catch {
    // Needs bootstrapping
  }

  // 3. Run bootstrap script
  console.log('[server.ts] Bootstrapping Python backend environment...');
  try {
    const setupScript = path.join(__dirname, 'scripts', 'setup-python.sh');
    execSync(`bash "${setupScript}"`, { stdio: 'inherit' });
    return venvPython;
  } catch (err) {
    console.error('[server.ts] Failed to run setup-python.sh:', err);
    return fs.existsSync(venvPython) ? venvPython : 'python3';
  }
}

/**
 * Launches the FastAPI Uvicorn backend process and monitors its lifecycle.
 */
function launchBackend() {
  if (isShuttingDown) return;

  const pythonCmd = ensurePythonEnvironment();
  console.log(`[server.ts] Starting FastAPI Uvicorn backend on port ${BACKEND_PORT}...`);

  backendProcess = spawn(pythonCmd, [
    '-m', 'uvicorn',
    'backend.app.main:app',
    '--host', '0.0.0.0',
    '--port', String(BACKEND_PORT),
  ], {
    stdio: 'inherit',
    env: {
      ...process.env,
      PYTHONPATH: `${path.join(__dirname, '.venv', 'lib', 'python3.10', 'site-packages')}:${__dirname}:${process.env.PYTHONPATH || ''}`,
    },
  });

  backendProcess.on('error', (err: any) => {
    console.error('[server.ts] Backend process error:', err.message);
  });

  backendProcess.on('exit', (code: number | null, signal: string | null) => {
    isBackendHealthy = false;
    console.warn(`[server.ts] Backend process exited (code: ${code}, signal: ${signal})`);
    if (!isShuttingDown) {
      console.log('[server.ts] Automatically restarting backend process in 2 seconds...');
      setTimeout(launchBackend, 2000);
    }
  });

  pollBackendReadiness();
}

/**
 * Periodically polls the backend health endpoint during startup until it confirms healthy.
 */
function pollBackendReadiness(attempts = 0, maxAttempts = 30) {
  if (isShuttingDown || isBackendHealthy) return;

  const req = http.get(`http://127.0.0.1:${BACKEND_PORT}/api/v1/health`, (res) => {
    if (res.statusCode === 200) {
      isBackendHealthy = true;
      console.log(`[server.ts] SentinelOps AI backend is ready and healthy on port ${BACKEND_PORT}.`);
    } else if (attempts < maxAttempts) {
      setTimeout(() => pollBackendReadiness(attempts + 1, maxAttempts), 500);
    }
  });

  req.on('error', () => {
    if (attempts < maxAttempts) {
      setTimeout(() => pollBackendReadiness(attempts + 1, maxAttempts), 500);
    }
  });
}

// Start backend supervisor
launchBackend();

/**
 * Proxies API requests to the FastAPI backend with retry resilience on startup.
 */
function proxyApiRequest(req: express.Request, res: express.Response, attempt = 1, maxAttempts = 8) {
  const options: http.RequestOptions = {
    hostname: '127.0.0.1',
    port: BACKEND_PORT,
    path: req.originalUrl,
    method: req.method,
    headers: {
      ...req.headers,
      host: `127.0.0.1:${BACKEND_PORT}`,
    },
  };

  const proxyReq = http.request(options, (proxyRes) => {
    res.writeHead(proxyRes.statusCode || 500, proxyRes.headers);
    proxyRes.pipe(res, { end: true });
  });

  proxyReq.on('error', (err: any) => {
    if ((err.code === 'ECONNREFUSED' || err.code === 'ECONNRESET') && attempt < maxAttempts && !res.headersSent) {
      setTimeout(() => {
        if (!res.headersSent) {
          proxyApiRequest(req, res, attempt + 1, maxAttempts);
        }
      }, 350);
      return;
    }

    console.error(`[server.ts] API Proxy error (${req.method} ${req.originalUrl}):`, err.message);
    if (!res.headersSent) {
      res.status(502).json({
        error: {
          code: 'BAD_GATEWAY',
          message: 'Unable to connect to SentinelOps AI backend service.',
          status_code: 502,
        },
      });
    }
  });

  req.pipe(proxyReq, { end: true });
}

// Healthz endpoint for container orchestrator readiness checks
app.get('/healthz', (_req, res) => {
  res.status(isBackendHealthy ? 200 : 503).json({
    status: isBackendHealthy ? 'ready' : 'warming_up',
    backend_port: BACKEND_PORT,
  });
});

// Proxy all /api requests to FastAPI
app.use('/api', (req, res) => {
  proxyApiRequest(req, res);
});

// Serve frontend production build assets
const distPath = path.join(__dirname, 'dist');
app.use(express.static(distPath));

// SPA fallback for HTML5 history API navigation
app.get('*', (_req, res) => {
  res.sendFile(path.join(distPath, 'index.html'));
});

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`[server.ts] SentinelOps AI production server listening on port ${PORT}`);
  console.log(`[server.ts] Proxying /api -> http://127.0.0.1:${BACKEND_PORT}`);
});

function handleShutdown() {
  if (isShuttingDown) return;
  isShuttingDown = true;
  console.log('[server.ts] Gracefully shutting down...');
  server.close();
  if (backendProcess) {
    backendProcess.kill('SIGTERM');
  }
}

process.on('SIGTERM', handleShutdown);
process.on('SIGINT', handleShutdown);
