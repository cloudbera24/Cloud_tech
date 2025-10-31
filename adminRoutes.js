// 📄 adminRoutes.js
const express = require('express');
const router = express.Router();
const connectionManager = require('./connectionManager');

function isAdmin(req, res, next) {
    next(); // Allow all access for now
}

router.get('/connections', isAdmin, (req, res) => {
    try {
        const connections = connectionManager.getAllConnections();
        const stats = connectionManager.getStats();
        const totalMessages = connections.reduce((sum, conn) => sum + (conn.messageCount || 0), 0);
        stats.totalMessages = totalMessages;
        
        res.json({
            success: true,
            connections: connections,
            stats: stats,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('Error getting connections:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

router.get('/connections/:id', isAdmin, (req, res) => {
    try {
        const connection = connectionManager.getConnection(req.params.id);
        if (!connection) {
            return res.status(404).json({
                success: false,
                error: 'Connection not found'
            });
        }
        res.json({
            success: true,
            connection: connection
        });
    } catch (error) {
        console.error('Error getting connection:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

router.post('/connections/:id/shutdown', isAdmin, (req, res) => {
    try {
        const success = connectionManager.shutdownConnection(req.params.id);
        if (!success) {
            return res.status(404).json({
                success: false,
                error: 'Connection not found or already shutdown'
            });
        }
        res.json({
            success: true,
            message: 'Connection shutdown successfully'
        });
    } catch (error) {
        console.error('Error shutting down connection:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

router.post('/connections/:id/restart', isAdmin, (req, res) => {
    try {
        const success = connectionManager.restartConnection(req.params.id);
        if (!success) {
            return res.status(404).json({
                success: false,
                error: 'Connection not found'
            });
        }
        res.json({
            success: true,
            message: 'Connection restart initiated'
        });
    } catch (error) {
        console.error('Error restarting connection:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

router.post('/connections/shutdown-all', isAdmin, (req, res) => {
    try {
        const connections = connectionManager.getAllConnections();
        let shutdownCount = 0;
        connections.forEach(connection => {
            if (connection.status === 'connected') {
                if (connectionManager.shutdownConnection(connection.id)) {
                    shutdownCount++;
                }
            }
        });
        res.json({
            success: true,
            message: `Shutdown ${shutdownCount} connections`,
            shutdownCount: shutdownCount
        });
    } catch (error) {
        console.error('Error shutting down all connections:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

router.post('/connections/restart-all', isAdmin, (req, res) => {
    try {
        const connections = connectionManager.getAllConnections();
        let restartCount = 0;
        connections.forEach(connection => {
            if (connectionManager.restartConnection(connection.id)) {
                restartCount++;
            }
        });
        res.json({
            success: true,
            message: `Restart initiated for ${restartCount} connections`,
            restartCount: restartCount
        });
    } catch (error) {
        console.error('Error restarting all connections:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

router.post('/connections/cleanup', isAdmin, (req, res) => {
    try {
        const cleanedCount = connectionManager.cleanupOldConnections();
        res.json({
            success: true,
            message: `Cleaned up ${cleanedCount} old connections`,
            cleaned: cleanedCount
        });
    } catch (error) {
        console.error('Error cleaning up connections:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

router.get('/stats', isAdmin, (req, res) => {
    try {
        const stats = connectionManager.getStats();
        const connections = connectionManager.getAllConnections();
        const totalMessages = connections.reduce((sum, conn) => sum + (conn.messageCount || 0), 0);
        stats.totalMessages = totalMessages;
        
        res.json({
            success: true,
            stats: stats,
            serverInfo: {
                uptime: process.uptime(),
                memory: process.memoryUsage(),
                version: '1.0.0',
                name: 'Cloud Tech'
            }
        });
    } catch (error) {
        console.error('Error getting stats:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

router.get('/activity', isAdmin, (req, res) => {
    try {
        const log = connectionManager.getActivityLog();
        res.json({
            success: true,
            activity: log,
            count: log.length
        });
    } catch (error) {
        console.error('Error getting activity log:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

router.get('/health', (req, res) => {
    res.json({
        success: true,
        status: 'operational',
        timestamp: new Date().toISOString(),
        service: 'Cloud Tech Admin API'
    });
});

module.exports = router;
