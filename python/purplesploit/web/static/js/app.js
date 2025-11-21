/**
 * PurpleSploit Web Portal
 * API Client and Utilities
 */

// API Configuration
const API_BASE_URL = window.location.origin;

// API Client
const API = {
    /**
     * Make a GET request to the API
     */
    async get(endpoint) {
        try {
            const response = await fetch(`${API_BASE_URL}${endpoint}`);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            console.error(`Error fetching ${endpoint}:`, error);
            throw error;
        }
    },

    /**
     * Make a POST request to the API
     */
    async post(endpoint, data) {
        try {
            const response = await fetch(`${API_BASE_URL}${endpoint}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data),
            });
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            console.error(`Error posting to ${endpoint}:`, error);
            throw error;
        }
    },

    /**
     * Get overview statistics
     */
    async getStats() {
        const stats = await this.get('/api/stats/overview');
        // Add total_exploits if not present (for backward compatibility)
        if (!stats.total_exploits) {
            try {
                const exploits = await this.get('/api/exploits');
                stats.total_exploits = exploits.length;
            } catch (error) {
                stats.total_exploits = 0;
            }
        }
        return stats;
    },

    /**
     * Get all targets
     */
    async getTargets() {
        return await this.get('/api/targets');
    },

    /**
     * Get all credentials
     */
    async getCredentials() {
        return await this.get('/api/credentials');
    },

    /**
     * Get all services
     */
    async getServices() {
        return await this.get('/api/services');
    },

    /**
     * Get services for a specific target
     */
    async getServicesForTarget(target) {
        return await this.get(`/api/services/${target}`);
    },

    /**
     * Get all exploits
     */
    async getExploits() {
        return await this.get('/api/exploits');
    },

    /**
     * Get exploits for a specific target
     */
    async getExploitsForTarget(target) {
        return await this.get(`/api/exploits/target/${target}`);
    },

    /**
     * Get comprehensive target analysis
     */
    async getTargetAnalysis(target) {
        return await this.get(`/api/analysis/${target}`);
    },

    /**
     * Execute a command
     */
    async executeCommand(command, timeout = 300) {
        return await this.post('/api/execute', { command, timeout });
    },

    /**
     * Run nmap scan
     */
    async runNmapScan(target, scanType = '-sV', ports = null) {
        return await this.post('/api/scan/nmap', {
            target,
            scan_type: scanType,
            ports,
        });
    },
};

// Utility Functions
const Utils = {
    /**
     * Format date to readable string
     */
    formatDate(dateString) {
        if (!dateString) return 'N/A';
        const date = new Date(dateString);
        return date.toLocaleString();
    },

    /**
     * Format large numbers with commas
     */
    formatNumber(num) {
        return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    },

    /**
     * Escape HTML to prevent XSS
     */
    escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;',
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    },

    /**
     * Show a toast notification
     */
    showToast(message, type = 'info') {
        // Simple console log for now - can be enhanced with a toast library
        console.log(`[${type.toUpperCase()}] ${message}`);
    },

    /**
     * Copy text to clipboard
     */
    async copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            this.showToast('Copied to clipboard!', 'success');
            return true;
        } catch (error) {
            console.error('Failed to copy:', error);
            this.showToast('Failed to copy to clipboard', 'error');
            return false;
        }
    },

    /**
     * Debounce function for search inputs
     */
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    /**
     * Get service severity level
     */
    getServiceSeverity(serviceName) {
        const critical = ['smb', 'rdp', 'telnet', 'ftp', 'mssql'];
        const warning = ['ssh', 'mysql', 'postgresql', 'winrm'];

        if (critical.includes(serviceName.toLowerCase())) {
            return 'critical';
        } else if (warning.includes(serviceName.toLowerCase())) {
            return 'warning';
        }
        return 'info';
    },

    /**
     * Get service icon
     */
    getServiceIcon(serviceName) {
        const icons = {
            'http': '🌐',
            'https': '🔒',
            'ssh': '🔐',
            'ftp': '📁',
            'smb': '📂',
            'rdp': '🖥️',
            'mssql': '🗄️',
            'mysql': '🗄️',
            'postgresql': '🗄️',
            'ldap': '📋',
            'winrm': '⚡',
            'telnet': '📟',
        };
        return icons[serviceName.toLowerCase()] || '🔧';
    },

    /**
     * Calculate risk score for a target
     */
    calculateRiskScore(services, exploits) {
        let score = 0;

        // Base score from number of services
        score += services.length * 5;

        // Critical services add more points
        const criticalServices = services.filter(s =>
            ['smb', 'rdp', 'telnet', 'ftp', 'mssql'].includes(s.service)
        );
        score += criticalServices.length * 20;

        // Exploits add significant points
        score += exploits.length * 15;

        // Cap at 100
        return Math.min(100, score);
    },

    /**
     * Get risk level from score
     */
    getRiskLevel(score) {
        if (score >= 80) return { level: 'Critical', class: 'danger' };
        if (score >= 60) return { level: 'High', class: 'warning' };
        if (score >= 40) return { level: 'Medium', class: 'info' };
        if (score >= 20) return { level: 'Low', class: 'success' };
        return { level: 'Minimal', class: 'success' };
    },

    /**
     * Group array by key
     */
    groupBy(array, key) {
        return array.reduce((result, item) => {
            const group = item[key];
            if (!result[group]) {
                result[group] = [];
            }
            result[group].push(item);
            return result;
        }, {});
    },

    /**
     * Sort array by multiple keys
     */
    sortBy(array, ...keys) {
        return array.sort((a, b) => {
            for (const key of keys) {
                if (a[key] < b[key]) return -1;
                if (a[key] > b[key]) return 1;
            }
            return 0;
        });
    },
};

// Export for use in other scripts
window.API = API;
window.Utils = Utils;

// Auto-refresh functionality (optional)
class AutoRefresh {
    constructor(interval = 30000) {
        this.interval = interval;
        this.enabled = false;
        this.timer = null;
        this.callbacks = [];
    }

    start() {
        if (this.enabled) return;
        this.enabled = true;
        this.timer = setInterval(() => {
            this.refresh();
        }, this.interval);
    }

    stop() {
        if (!this.enabled) return;
        this.enabled = false;
        clearInterval(this.timer);
        this.timer = null;
    }

    onRefresh(callback) {
        this.callbacks.push(callback);
    }

    async refresh() {
        for (const callback of this.callbacks) {
            try {
                await callback();
            } catch (error) {
                console.error('Refresh callback error:', error);
            }
        }
    }
}

window.AutoRefresh = AutoRefresh;

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', () => {
    console.log('🔮 PurpleSploit Web Portal loaded');

    // Add any global event listeners here
    setupGlobalHandlers();
});

function setupGlobalHandlers() {
    // Handle external links
    document.querySelectorAll('a[target="_blank"]').forEach(link => {
        link.rel = 'noopener noreferrer';
    });

    // Handle keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        // Ctrl/Cmd + K for search (if implemented)
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            const searchInput = document.getElementById('search-input');
            if (searchInput) {
                searchInput.focus();
            }
        }
    });
}

// Error handling
window.addEventListener('error', (event) => {
    console.error('Global error:', event.error);
});

window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
});
