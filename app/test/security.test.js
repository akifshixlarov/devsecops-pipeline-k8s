'use strict';

const request = require('supertest');
const createApp = require('../src/app');

describe('security baseline', () => {
  const app = createApp();

  test('GET /health returns 200 with minimal, predictable body', async () => {
    const res = await request(app).get('/health');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'ok' });
  });

  test('core security headers are present (helmet) and fingerprinting header is removed', async () => {
    const res = await request(app).get('/');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });

  test('rejects oversized JSON payloads (DoS/resource-exhaustion guard)', async () => {
    const bigTitle = 'a'.repeat(20_000);
    const res = await request(app)
      .post('/api/tasks')
      .set('Content-Type', 'application/json')
      .send({ title: bigTitle });
    expect(res.status).toBe(413);
  });

  test('rejects task creation with missing/invalid title', async () => {
    const res = await request(app)
      .post('/api/tasks')
      .set('Content-Type', 'application/json')
      .send({});
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_request');
  });

  test('unknown routes return a generic 404 without leaking internal structure', async () => {
    const res = await request(app).get('/definitely-not-a-real-route');
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: 'not_found', message: 'resource not found' });
  });

  test('malformed JSON body never leaks a stack trace to the client', async () => {
    const res = await request(app)
      .post('/api/tasks')
      .set('Content-Type', 'application/json')
      .send('{ this is not valid json');
    expect(res.status).toBeGreaterThanOrEqual(400);
    // Stack trace "at functionName (file:line:col)" formatına bənzər heç nə qayıtmamalıdır.
    expect(JSON.stringify(res.body)).not.toMatch(/at\s+\S+\s*\(.*:\d+:\d+\)/);
  });

  test('path param that is not a UUID is rejected before a store lookup happens', async () => {
    const res = await request(app).get('/api/tasks/not-a-uuid');
    expect(res.status).toBe(400);
  });

  test('create → read → delete lifecycle works and IDs are unpredictable UUIDv4-shaped values', async () => {
    const create = await request(app)
      .post('/api/tasks')
      .set('Content-Type', 'application/json')
      .send({ title: 'write threat model' });
    expect(create.status).toBe(201);
    expect(create.body.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
    );

    const read = await request(app).get(`/api/tasks/${create.body.id}`);
    expect(read.status).toBe(200);

    const del = await request(app).delete(`/api/tasks/${create.body.id}`);
    expect(del.status).toBe(204);

    const readAgain = await request(app).get(`/api/tasks/${create.body.id}`);
    expect(readAgain.status).toBe(404);
  });
});
