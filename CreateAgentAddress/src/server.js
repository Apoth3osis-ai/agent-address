const express = require('express');
const path = require('path');
const { generate } = require('./generate');

const app = express();
const PORT = Number(process.env.PORT) || 3000;

app.use(express.static(path.join(__dirname, '..', 'public')));

app.get('/api/generate', (req, res) => {
  try {
    const idx = Number(req.query.index || 0);
    const words = Number(req.query.words || 12);
    const mnemonic = req.query.mnemonic || undefined;
    const payload = generate({ index: idx, words, mnemonic, json: true });
    res.json(payload);
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: err.message || 'Failed to generate wallet' });
  }
});

function start(port) {
  const server = app.listen(port);

  server.on('listening', () => {
    const actual = server.address().port;
    console.log(`Agent address UI running on http://localhost:${actual}`);
  });

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.warn(`Port ${port} in use, picking a free port...`);
      // Retry on an ephemeral port
      start(0);
    } else {
      console.error('Server error:', err);
      process.exit(1);
    }
  });
}

start(PORT);
