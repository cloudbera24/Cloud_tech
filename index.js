// 📄 index.js
const express = require('express');
const app = express();
const path = require('path');
const bodyParser = require("body-parser");
const PORT = process.env.PORT || 8000;

// Import routes - make sure these files exist and export correctly
const codeRouter = require('./pair');
const adminRouter = require('./adminRoutes');

require('events').EventEmitter.defaultMaxListeners = 500;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// API routes
app.use('/code', codeRouter);
app.use('/admin', adminRouter);

// Page routes
app.get('/pair', (req, res) => {
    res.sendFile(path.join(__dirname, 'pair.html'));
});

app.get('/admin-dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin-dashboard.html'));
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'main.html'));
});

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
