// 📄 connectionManager.js
const { makeid } = require('./Id');

class ConnectionManager {
    constructor() {
        this.connections = new Map();
        this.connectionStats = {
            totalConnections: 0,
            activeConnections: 0,
            disconnectedConnections: 0,
            restartingConnections: 0
        };
        this.activityLog = [];
        this.maxLogSize = 1000;
    }

    addConnection(conn, username, ipAddress) {
        const connectionId = makeid(8);
        const connectionInfo = {
            id: connectionId,
            username: username || 'Unknown',
            ipAddress: ipAddress,
            conn: conn,
            status: 'connected',
            connectedAt: new Date(),
            lastActivity: new Date(),
            qrScanned: false,
            messageCount: 0,
            lastMessageTime: null
        };

        this.connections.set(connectionId, connectionInfo);
        this.updateStats();
        this.logActivity('CONNECTION_ADDED', `New connection: ${username} (${ipAddress})`);
        return connectionId;
    }

    updateConnection(connectionId, updates) {
        if (this.connections.has(connectionId)) {
            const connection = this.connections.get(connectionId);
            Object.assign(connection, updates, { lastActivity: new Date() });
            this.connections.set(connectionId, connection);
            this.updateStats();
            return true;
        }
        return false;
    }

    recordMessage(connectionId) {
        if (this.connections.has(connectionId)) {
            const connection = this.connections.get(connectionId);
            connection.messageCount = (connection.messageCount || 0) + 1;
            connection.lastMessageTime = new Date();
            this.connections.set(connectionId, connection);
            return true;
        }
        return false;
    }

    removeConnection(connectionId) {
        if (this.connections.has(connectionId)) {
            const connection = this.connections.get(connectionId);
            connection.status = 'disconnected';
            connection.disconnectedAt = new Date();
            this.updateStats();
            return true;
        }
        return false;
    }

    getAllConnections() {
        return Array.from(this.connections.values());
    }

    getActiveConnections() {
        return this.getAllConnections().filter(conn => conn.status === 'connected');
    }

    getConnection(connectionId) {
        return this.connections.get(connectionId);
    }

    shutdownConnection(connectionId) {
        const connection = this.getConnection(connectionId);
        if (connection && connection.conn) {
            try {
                connection.conn.ws.close();
                this.updateConnection(connectionId, { 
                    status: 'shutdown',
                    disconnectedAt: new Date()
                });
                return true;
            } catch (error) {
                console.error(`Error shutting down connection ${connectionId}:`, error);
                return false;
            }
        }
        return false;
    }

    async restartConnection(connectionId) {
        const connection = this.getConnection(connectionId);
        if (connection) {
            if (connection.conn && connection.status === 'connected') {
                connection.conn.ws.close();
            }
            
            const number = connection.username;
            if (global.activeSockets && global.activeSockets.has(number)) {
                global.activeSockets.delete(number);
            }
            
            this.updateConnection(connectionId, {
                status: 'restarting',
                lastActivity: new Date()
            });
            return true;
        }
        return false;
    }

    updateStats() {
        const allConnections = this.getAllConnections();
        this.connectionStats.totalConnections = allConnections.length;
        this.connectionStats.activeConnections = allConnections.filter(conn => 
            conn.status === 'connected'
        ).length;
        this.connectionStats.disconnectedConnections = allConnections.filter(conn => 
            conn.status === 'disconnected' || conn.status === 'shutdown'
        ).length;
    }

    getStats() {
        return this.connectionStats;
    }

    getActivityLog(limit = 50) {
        return this.activityLog.slice(-limit).reverse();
    }

    logActivity(type, message) {
        const logEntry = {
            timestamp: new Date(),
            type: type,
            message: message,
            id: makeid(4)
        };
        
        this.activityLog.push(logEntry);
        if (this.activityLog.length > this.maxLogSize) {
            this.activityLog = this.activityLog.slice(-this.maxLogSize);
        }
    }

    cleanupOldConnections() {
        const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
        let cleanedCount = 0;

        for (const [connectionId, connection] of this.connections) {
            if ((connection.status === 'disconnected' || connection.status === 'shutdown') &&
                connection.disconnectedAt && connection.disconnectedAt < oneHourAgo) {
                this.connections.delete(connectionId);
                cleanedCount++;
            }
        }

        if (cleanedCount > 0) {
            this.updateStats();
        }
        return cleanedCount;
    }
}

const connectionManager = new ConnectionManager();
setInterval(() => {
    connectionManager.cleanupOldConnections();
}, 30 * 60 * 1000);

module.exports = connectionManager;
