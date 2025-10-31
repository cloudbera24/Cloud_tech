const express = require('express');
const router = express.Router();
const fs = require('fs-extra');
const path = require('path');

// Import connection manager
const connectionManager = require('./connectionManager');

// Admin authentication middleware
const authenticateAdmin = (req, res, next) => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Admin authentication required' });
    }
    
    // In production, use proper JWT or session-based auth
    const token = authHeader.replace('Bearer ', '');
    if (token !== process.env.ADMIN_TOKEN && token !== 'cloudtech_admin_2024') {
        return res.status(401).json({ error: 'Invalid admin token' });
    }
    
    next();
};

// Get all active connections
router.get('/connections', authenticateAdmin, (req, res) => {
    try {
        const activeConnections = connectionManager.getActiveConnections();
        const connectionStats = connectionManager.getConnectionStats();
        
        res.json({
            status: 'success',
            data: {
                connections: activeConnections,
                statistics: connectionStats,
                timestamp: new Date().toISOString()
            }
        });
    } catch (error) {
        res.status(500).json({ 
            status: 'error', 
            error: 'Failed to fetch connections',
            details: error.message 
        });
    }
});

// Get detailed connection info
router.get('/connections/:number', authenticateAdmin, (req, res) => {
    try {
        const { number } = req.params;
        const connectionInfo = connectionManager.getConnectionInfo(number);
        
        if (!connectionInfo) {
            return res.status(404).json({ 
                status: 'error', 
                error: 'Connection not found' 
            });
        }
        
        res.json({
            status: 'success',
            data: connectionInfo
        });
    } catch (error) {
        res.status(500).json({ 
            status: 'error', 
            error: 'Failed to fetch connection info',
            details: error.message 
        });
    }
});

// Shutdown specific connection
router.post('/connections/:number/shutdown', authenticateAdmin, (req, res) => {
    try {
        const { number } = req.params;
        const result = connectionManager.shutdownConnection(number);
        
        res.json({
            status: 'success',
            message: `Connection ${number} shutdown initiated`,
            data: result
        });
    } catch (error) {
        res.status(500).json({ 
            status: 'error', 
            error: 'Failed to shutdown connection',
            details: error.message 
        });
    }
});

// Restart specific connection
router.post('/connections/:number/restart', authenticateAdmin, (req, res) => {
    try {
        const { number } = req.params;
        const result = connectionManager.restartConnection(number);
        
        res.json({
            status: 'success',
            message: `Connection ${number} restart initiated`,
            data: result
        });
    } catch (error) {
        res.status(500).json({ 
            status: 'error', 
            error: 'Failed to restart connection',
            details: error.message 
        });
    }
});

// Shutdown all connections
router.post('/connections/shutdown-all', authenticateAdmin, (req, res) => {
    try {
        const result = connectionManager.shutdownAllConnections();
        
        res.json({
            status: 'success',
            message: 'All connections shutdown initiated',
            data: result
        });
    } catch (error) {
        res.status(500).json({ 
            status: 'error', 
            error: 'Failed to shutdown all connections',
            details: error.message 
        });
    }
});

// Restart all connections
router.post('/connections/restart-all', authenticateAdmin, (req, res) => {
    try {
        const result = connectionManager.restartAllConnections();
        
        res.json({
            status: 'success',
            message: 'All connections restart initiated',
            data: result
        });
    } catch (error) {
        res.status(500).json({ 
            status: 'error', 
            error: 'Failed to restart all connections',
            details: error.message 
        });
    }
});

// Get system statistics
router.get('/statistics', authenticateAdmin, (req, res) => {
    try {
        const stats = connectionManager.getSystemStatistics();
        
        res.json({
            status: 'success',
            data: stats
        });
    } catch (error) {
        res.status(500).json({ 
            status: 'error', 
            error: 'Failed to fetch statistics',
            details: error.message 
        });
    }
});

// Clean up inactive sessions
router.post('/cleanup', authenticateAdmin, (req, res) => {
    try {
        const result = connectionManager.cleanupInactiveSessions();
        
        res.json({
            status: 'success',
            message: 'Cleanup completed',
            data: result
        });
    } catch (error) {
        res.status(500).json({ 
            status: 'error', 
            error: 'Failed to cleanup sessions',
            details: error.message 
        });
    }
});

module.exports = router;
