const express = require('express');
const app = express();
__path = process.cwd()
const bodyParser = require("body-parser");
const PORT = process.env.PORT || 8000;
let code = require('./pair');

// Import admin routes
const adminRoutes = require('./adminRoutes');

require('events').EventEmitter.defaultMaxListeners = 500;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Routes
app.use('/code', code);
app.use('/admin', adminRoutes); // Admin API routes
app.use('/pair', async (req, res, next) => {
    res.sendFile(__path + '/pair.html');
});
app.use('/dashboard', async (req, res, next) => {
    res.sendFile(__path + '/admin-dashboard.html');
});
app.use('/', async (req, res, next) => {
    res.sendFile(__path + '/main.html');
});

// ✅ Changed here to bind on 0.0.0.0
app.listen(PORT, '0.0.0.0', () => {
    console.log(`
╔══════════════════════════════════════╗
║           CLOUD TECH v2.0            ║
║      Professional Bot Management     ║
║           Developed by Bera          ║
╚══════════════════════════════════════╝

Server running on http://0.0.0.0:` + PORT);
console.log(`🌐 User Interface: http://0.0.0.0:${PORT}`);
console.log(`🔧 Admin Dashboard: http://0.0.0.0:${PORT}/dashboard`);
});

module.exports = app;
