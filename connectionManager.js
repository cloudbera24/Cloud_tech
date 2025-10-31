const fs = require('fs-extra');
const path = require('path');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

class ConnectionManager {
    constructor() {
        this.activeConnections = new Map();
        this.connectionStats = {
            totalConnections: 0,
            activeConnections: 0,
            totalUptime: 0,
            totalMessages: 0,
            peakConnections: 0
        };
        this.initialize();
    }

    initialize() {
        // Load existing connection data
        this.loadConnectionData();
        
        // Start periodic cleanup
        setInterval(() => {
            this.cleanupInactiveSessions();
        }, 300000); // 5 minutes
    }

    // Add connection to management
    addConnection(number, socket, metadata = {}) {
        const connectionData = {
            number,
            socket,
            metadata,
            status: 'active',
            connectedAt: new Date(),
            lastActivity: new Date(),
            messageCount: 0,
            uptime: 0,
            ping: 0
        };

        this.activeConnections.set(number, connectionData);
        this.updateStats();
        
        console.log(`✅ Connection added: ${number}`);
        return connectionData;
    }

    // Remove connection
    removeConnection(number) {
        const connection = this.activeConnections.get(number);
        if (connection) {
            connection.status = 'inactive';
            connection.uptime = Date.now() - connection.connectedAt;
            this.activeConnections.delete(number);
            this.updateStats();
            
            console.log(`❌ Connection removed: ${number}`);
            return connection;
        }
        return null;
    }

    // Update connection activity
    updateActivity(number) {
        const connection = this.activeConnections.get(number);
        if (connection) {
            connection.lastActivity = new Date();
            connection.messageCount++;
            this.updateStats();
        }
    }

    // Get all active connections
    getActiveConnections() {
        const connections = [];
        
        this.activeConnections.forEach((connection, number) => {
            connections.push({
                number,
                status: connection.status,
                connectedAt: connection.connectedAt,
                lastActivity: connection.lastActivity,
                uptime: Date.now() - connection.connectedAt,
                messageCount: connection.messageCount,
                ping: connection.ping,
                metadata: connection.metadata
            });
        });

        return connections.sort((a, b) => b.connectedAt - a.connectedAt);
    }

    // Get connection statistics
    getConnectionStats() {
        const connections = this.getActiveConnections();
        const now = Date.now();
        
        return {
            totalActive: connections.length,
            totalMessages: connections.reduce((sum, conn) => sum + conn.messageCount, 0),
            averageUptime: connections.length > 0 ? 
                connections.reduce((sum, conn) => sum + conn.uptime, 0) / connections.length : 0,
            recentActivity: connections.filter(conn => 
                now - conn.lastActivity < 300000 // 5 minutes
            ).length
        };
    }

    // Get detailed connection info
    getConnectionInfo(number) {
        const connection = this.activeConnections.get(number);
        if (!connection) return null;

        const uptime = Date.now() - connection.connectedAt;
        const hours = Math.floor(uptime / (1000 * 60 * 60));
        const minutes = Math.floor((uptime % (1000 * 60 * 60)) / (1000 * 60));
        
        return {
            number,
            status: connection.status,
            connectedAt: connection.connectedAt,
            lastActivity: connection.lastActivity,
            uptime: `${hours}h ${minutes}m`,
            messageCount: connection.messageCount,
            ping: connection.ping,
            metadata: connection.metadata,
            performance: this.calculatePerformance(connection)
        };
    }

    // Calculate connection performance
    calculatePerformance(connection) {
        const uptime = Date.now() - connection.connectedAt;
        const messagesPerMinute = connection.messageCount / (uptime / (1000 * 60));
        
        let status = 'excellent';
        if (messagesPerMinute < 1) status = 'low';
        else if (messagesPerMinute < 5) status = 'good';
        else if (messagesPerMinute < 10) status = 'high';
        
        return {
            status,
            messagesPerMinute: Math.round(messagesPerMinute * 100) / 100,
            reliability: '95%' // Placeholder
        };
    }

    // Shutdown specific connection
    shutdownConnection(number) {
        const connection = this.activeConnections.get(number);
        if (connection && connection.socket) {
            try {
                connection.socket.ws.close();
                this.removeConnection(number);
                return { success: true, message: `Connection ${number} shutdown successfully` };
            } catch (error) {
                return { success: false, error: error.message };
            }
        }
        return { success: false, error: 'Connection not found' };
    }

    // Restart specific connection
    restartConnection(number) {
        const connection = this.activeConnections.get(number);
        if (connection) {
            this.shutdownConnection(number);
            // In a real implementation, you'd trigger reconnection logic here
            return { success: true, message: `Connection ${number} restart initiated` };
        }
        return { success: false, error: 'Connection not found' };
    }

    // Shutdown all connections
    shutdownAllConnections() {
        const results = [];
        this.activeConnections.forEach((connection, number) => {
            const result = this.shutdownConnection(number);
            results.push({ number, ...result });
        });
        return results;
    }

    // Restart all connections
    restartAllConnections() {
        const results = [];
        this.activeConnections.forEach((connection, number) => {
            const result = this.restartConnection(number);
            results.push({ number, ...result });
        });
        return results;
    }

    // Get system statistics
    getSystemStatistics() {
        const connections = this.getActiveConnections();
        const now = Date.now();
        
        const active24h = connections.filter(conn => 
            now - conn.connectedAt < 24 * 60 * 60 * 1000
        ).length;

        return {
            totalConnections: this.connectionStats.totalConnections,
            activeConnections: connections.length,
            connections24h: active24h,
            totalMessages: this.connectionStats.totalMessages,
            systemUptime: process.uptime(),
            memoryUsage: process.memoryUsage(),
            nodeVersion: process.version,
            platform: process.platform
        };
    }

    // Cleanup inactive sessions
    cleanupInactiveSessions() {
        const now = Date.now();
        const inactiveThreshold = 30 * 60 * 1000; // 30 minutes
        
        let cleaned = 0;
        this.activeConnections.forEach((connection, number) => {
            if (now - connection.lastActivity > inactiveThreshold) {
                this.removeConnection(number);
                cleaned++;
            }
        });

        if (cleaned > 0) {
            console.log(`🧹 Cleaned up ${cleaned} inactive sessions`);
        }

        return { cleaned };
    }

    // Update statistics
    updateStats() {
        const connections = this.getActiveConnections();
        this.connectionStats.activeConnections = connections.length;
        this.connectionStats.totalMessages = connections.reduce((sum, conn) => sum + conn.messageCount, 0);
        
        if (connections.length > this.connectionStats.peakConnections) {
            this.connectionStats.peakConnections = connections.length;
        }
    }

    // Load connection data from storage
    async loadConnectionData() {
        try {
            const dataPath = path.join(__dirname, 'connection-data.json');
            if (await fs.pathExists(dataPath)) {
                const data = await fs.readJson(dataPath);
                this.connectionStats = { ...this.connectionStats, ...data.stats };
            }
        } catch (error) {
            console.log('No existing connection data found');
        }
    }

    // Save connection data to storage
    async saveConnectionData() {
        try {
            const dataPath = path.join(__dirname, 'connection-data.json');
            await fs.writeJson(dataPath, {
                stats: this.connectionStats,
                savedAt: new Date()
            });
        } catch (error) {
            console.error('Failed to save connection data:', error);
        }
    }
}

// Create singleton instance
const connectionManager = new ConnectionManager();

// Save data periodically
setInterval(() => {
    connectionManager.saveConnectionData();
}, 60000); // 1 minute

module.exports = connectionManager;
