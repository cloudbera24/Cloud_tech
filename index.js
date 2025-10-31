// 📄 index.js
const express = require('express');
const app = express();
__path = process.cwd()
const bodyParser = require("body-parser");
const PORT = process.env.PORT || 8000;
let code = require('./pair');
const adminRoutes = require('./adminRoutes');

require('events').EventEmitter.defaultMaxListeners = 500;

// API routes
app.use('/code', code);
app.use('/admin', adminRoutes);

// Page routes
app.use('/pair', async (req, res, next) => {
    res.sendFile(__path + '/pair.html');
});

app.use('/admin-dashboard', async (req, res, next) => {
    res.sendFile(__path + '/admin-dashboard.html');
});

app.use('/', async (req, res, next) => {
    res.sendFile(__path + '/main.html');
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        service: 'Cloud Tech WhatsApp Bot',
        timestamp: new Date().toISOString(),
        version: '1.0.0'
    });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({
        success: false,
        error: 'Endpoint not found',
        availableEndpoints: {
            user: ['/', '/pair'],
            admin: ['/admin-dashboard'],
            api: ['/code', '/admin', '/health']
        }
    });
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Server Error:', error);
    res.status(500).json({
        success: false,
        error: 'Internal server error',
        message: error.message
    });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`
🚀 Cloud Tech Server Started Successfully!
📱 User Pages: http://localhost:${PORT}/ & http://localhost:${PORT}/pair
📊 Admin Dashboard: http://localhost:${PORT}/admin-dashboard
🔧 API: http://localhost:${PORT}/code & http://localhost:${PORT}/admin
⚡ Port: ${PORT} | Binding: 0.0.0.0
Developed by Bera | Powered by Cloud Tech
`);
});

module.exports = app;
