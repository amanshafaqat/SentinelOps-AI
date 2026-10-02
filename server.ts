import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import http from 'http';
import { spawn } from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const BACKEND_PORT = 8001;

// Spawn Uvicorn backend process for standalone production execution
let backendProcess: any = null;
try {
  backendProcess = spawn('python3', [
    '-m', 'uvicorn',
    'backend.app.main:app',
    '--host', '0.0.0.0',
    '--port', String(BACKEND_PORT),
  ], {
    stdio: 'inherit',
    shell: true,
  });

  backendProcess.on('error', (err: any) => {
    console.error('Failed to start FastAPI backend process:', err);
  });
} catch (e) {
  console.warn('Backend process spawn notice:', e);
}

// Proxy /api requests to FastAPI backend on port 8001
app.use('/api', (req, res) => {
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

  proxyReq.on('error', (err) => {
    console.error('API Proxy error:', err.message);
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
});

// Serve frontend production build assets
const distPath = path.join(__dirname, 'dist');
app.use(express.static(distPath));

// SPA fallback for HTML5 history API navigation
app.get('*', (_req, res) => {
  res.sendFile(path.join(distPath, 'index.html'));
});

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`SentinelOps AI production server running on port ${PORT}`);
  console.log(`API proxy routing /api -> http://127.0.0.1:${BACKEND_PORT}`);
});

process.on('SIGTERM', () => {
  server.close();
  if (backendProcess) backendProcess.kill();
});
process.on('SIGINT', () => {
  server.close();
  if (backendProcess) backendProcess.kill();
});
