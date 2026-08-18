'use strict';

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const pinoHttp = require('pino-http');

const logger = require('./logger');
const tasksRouter = require('./routes/tasks');

function createApp() {
  const app = express();

  // Yalnız açıq şəkildə Ingress/LB arxasında olduğumuzu bildirdikdə etibar et.
  // Default: false — X-Forwarded-* header spoofing-in qarşısını alır.
  app.set('trust proxy', process.env.TRUST_PROXY === 'true');

  // "X-Powered-By: Express" header-i texnologiya barmaq izini (fingerprint) azaldır.
  app.disable('x-powered-by');

  // helmet(): təhlükəsizlik başlıqlarının bütün dəstini əlavə edir
  // (X-Content-Type-Options, HSTS, CSP baza qaydaları və s.)
  // Mitiqasiya edir: clickjacking, MIME sniffing, bəzi XSS vektorları.
  app.use(helmet());

  // CORS: default olaraq HEÇ bir origin-ə icazə verilmir (deny-by-default).
  // Konkret origin CORS_ORIGIN env dəyişəni ilə açıq şəkildə göstərilməlidir.
  app.use(
    cors({
      origin: process.env.CORS_ORIGIN || false,
    })
  );

  // Struktur (JSON) request logging — hər request unikal id ilə izlənə bilər.
  app.use(
    pinoHttp({
      logger,
      genReqId: (req) => req.headers['x-request-id'] || undefined,
    })
  );

  // Sadə tətbiq-səviyyəli rate limiting.
  // Mitiqasiya edir: STRIDE-D (Denial of Service) — bax threat-model § 3.9 T-D.
  app.use(
    rateLimit({
      windowMs: 60 * 1000,
      max: 100,
      standardHeaders: true,
      legacyHeaders: false,
    })
  );

  // Body ölçüsü limiti — həddindən artıq böyük payload-larla resurs tükənməsinin qarşısını alır.
  app.use(express.json({ limit: '10kb' }));

  app.get('/', (req, res) => {
    res.status(200).json({
      service: 'secure-cicd-capstone-app',
      status: 'ok',
    });
  });

  // Liveness/readiness probe üçün istifadə olunur (bax Phase 5 — K8s probes).
  app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok' });
  });

  app.use('/api/tasks', tasksRouter);

  // 404 — generic mesaj, daxili route strukturunu ifşa etmir.
  app.use((req, res) => {
    res.status(404).json({ error: 'not_found', message: 'resource not found' });
  });

  // Mərkəzi error handler.
  // Kritik qayda: HEÇ VAXT stack trace və ya daxili error.message client-ə göndərilmir
  // (mitiqasiya: STRIDE-I — Information Disclosure, bax threat-model § 3.8).
  // Gözlənilən client-error-ların (məs. body-parser-in 413/400-ü) HTTP statusu
  // qorunur, lakin mesaj həmişə generic, əvvəlcədən təyin olunmuş mətndir.
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (req.log) {
      req.log.error({ err }, 'unhandled error');
    } else {
      logger.error({ err }, 'unhandled error');
    }

    const upstreamStatus = err.status || err.statusCode;
    const isClientError = upstreamStatus >= 400 && upstreamStatus < 500;
    const status = isClientError ? upstreamStatus : 500;

    const genericMessage = {
      400: 'malformed request body',
      413: 'payload too large',
    }[status];

    res.status(status).json({
      error: status === 500 ? 'internal_error' : 'bad_request',
      message: genericMessage || (status === 500 ? 'unexpected server error' : 'invalid request'),
    });
  });

  return app;
}

module.exports = createApp;
