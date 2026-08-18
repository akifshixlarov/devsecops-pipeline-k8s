'use strict';

const pino = require('pino');

/**
 * Struktur (JSON) logging — SIEM/log aggregator-lara asanlıqla inteqrasiya üçün.
 * `redact` ilə həssas sahələr (Authorization header, cookie, password, token)
 * log-a heç vaxt açıq şəkildə yazılmır — bu, "Information Disclosure via logs"
 * (STRIDE-I, bax docs/threat-model.md 3.3) təhdidinin mitiqasiyasıdır.
 */
const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  redact: {
    paths: [
      'req.headers.authorization',
      'req.headers.cookie',
      'req.headers["x-api-key"]',
      '*.password',
      '*.token',
      '*.secret',
    ],
    remove: true,
  },
  formatters: {
    level(label) {
      return { level: label };
    },
  },
  timestamp: pino.stdTimeFunctions.isoTime,
});

module.exports = logger;
