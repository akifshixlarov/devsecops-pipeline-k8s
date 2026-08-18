'use strict';

/**
 * Distroless runtime image-də shell yoxdur, ona görə Docker HEALTHCHECK
 * exec-form ilə birbaşa bu skripti node binary vasitəsilə çağırır
 * (bax Dockerfile: HEALTHCHECK CMD ["node", "/app/healthcheck.js"]).
 * Heç bir xarici asılılıq istifadə etmir — yalnız Node.js built-in `http` modulu.
 */
const http = require('http');

const port = process.env.PORT || 3000;

const req = http.get(
  { host: '127.0.0.1', port, path: '/health', timeout: 2000 },
  (res) => {
    process.exit(res.statusCode === 200 ? 0 : 1);
  }
);

req.on('error', () => process.exit(1));
req.on('timeout', () => {
  req.destroy();
  process.exit(1);
});
