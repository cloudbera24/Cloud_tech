// [file name]: index.js
[file content begin]
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

app.listen(PORT, '0.0.0.0', () => {
    console.log(`
🚀 Cloud Tech Server Started Successfully!

📱 User Access Points:
   • Main Landing Page: http://localhost:${PORT}/
   • Pairing Interface: http://localhost:${PORT}/pair

📊 Admin Dashboard:
   • Control Panel: http://localhost:${PORT}/admin-dashboard

🔧 API Endpoints:
   • Pairing API: http://localhost:${PORT}/code
   • Admin API: http://localhost:${PORT}/admin

⚡ Server running on port: ${PORT}
🔒 Binding: 0.0.0.0

Developed by Bera
Powered by Cloud Tech
`);
});

module.exports = app;
[file content end]
