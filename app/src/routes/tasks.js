'use strict';

const express = require('express');
const { randomUUID } = require('crypto');

const router = express.Router();

/**
 * In-memory store.
 * Qəsdən: v1 capstone scope-unda persistent data store istifadə edilmir
 * (bax docs/threat-model.md § "Scope qeydi"). Bu, əlavə DB trust boundary-sini
 * scope-dan kənarda saxlayır və fokusu CI/CD security zəncirində saxlayır.
 */
const tasks = new Map();

const MAX_TITLE_LENGTH = 200;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function isValidTitle(title) {
  return (
    typeof title === 'string' &&
    title.trim().length > 0 &&
    title.length <= MAX_TITLE_LENGTH
  );
}

// GET /api/tasks — bütün task-ları qaytarır
router.get('/', (req, res) => {
  res.status(200).json({ items: Array.from(tasks.values()) });
});

// POST /api/tasks — yeni task yaradır (input validasiyası SAST/DAST üçün əsas hədəf)
router.post('/', (req, res) => {
  const body = req.body || {};
  const { title } = body;

  if (!isValidTitle(title)) {
    return res.status(400).json({
      error: 'invalid_request',
      message: `title tələb olunur, string olmalı və uzunluğu ${MAX_TITLE_LENGTH} simvoldan az olmalıdır`,
    });
  }

  const task = {
    id: randomUUID(),
    title: title.trim(),
    done: false,
    createdAt: new Date().toISOString(),
  };

  tasks.set(task.id, task);
  req.log.info({ taskId: task.id }, 'task created');
  return res.status(201).json(task);
});

// GET /api/tasks/:id — tək task
router.get('/:id', (req, res) => {
  if (!UUID_RE.test(req.params.id)) {
    return res.status(400).json({ error: 'invalid_request', message: 'id UUID formatında olmalıdır' });
  }
  const task = tasks.get(req.params.id);
  if (!task) {
    return res.status(404).json({ error: 'not_found', message: 'task tapılmadı' });
  }
  return res.status(200).json(task);
});

// DELETE /api/tasks/:id
router.delete('/:id', (req, res) => {
  if (!UUID_RE.test(req.params.id)) {
    return res.status(400).json({ error: 'invalid_request', message: 'id UUID formatında olmalıdır' });
  }
  const existed = tasks.delete(req.params.id);
  if (!existed) {
    return res.status(404).json({ error: 'not_found', message: 'task tapılmadı' });
  }
  req.log.info({ taskId: req.params.id }, 'task deleted');
  return res.status(204).send();
});

module.exports = router;
