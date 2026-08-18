'use strict';
// Düzəliş: secret environment variable-dan oxunur.
const DATABASE_PASSWORD = process.env.DATABASE_PASSWORD;
module.exports = { DATABASE_PASSWORD };
