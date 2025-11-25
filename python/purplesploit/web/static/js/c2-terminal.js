/**
 * PurpleSploit C2 Terminal
 * Interactive terminal interface with WebSocket support
 */

// Configuration
const API_BASE = window.location.origin;
const WS_BASE = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}`;

// Global state
let websocket = null;
let sessionId = 'default';
let commandHistory = [];
let historyIndex = -1;
let currentModule = null;
let modules = [];
let connectionAttempts = 0;
const MAX_CONNECTION_ATTEMPTS = 5;

// DOM Elements
let terminalOutput, terminalInput, promptText, statusDot, statusText;
let moduleList, moduleSearch, currentModuleDisplay, currentTargetDisplay;

/**
 * Initialize the terminal
 */
function initTerminal() {
    // Get DOM elements
    terminalOutput = document.getElementById('terminal-output');
    terminalInput = document.getElementById('terminal-input');
    promptText = document.getElementById('prompt-text');
    statusDot = document.querySelector('.status-dot');
    statusText = document.querySelector('.status-text');
    moduleList = document.getElementById('module-list');
    moduleSearch = document.getElementById('module-search');
    currentModuleDisplay = document.getElementById('current-module');
    currentTargetDisplay = document.getElementById('current-target');

    // Generate or get session ID
    sessionId = getSessionId();
    document.getElementById('session-id').textContent = sessionId;

    // Setup event listeners
    terminalInput.addEventListener('keydown', handleKeyDown);
    moduleSearch.addEventListener('input', handleModuleSearch);

    // Connect WebSocket
    connectWebSocket();

    // Load modules
    loadModules();

    // Update context periodically
    setInterval(updateContext, 5000);
}

/**
 * Generate or retrieve session ID
 */
function getSessionId() {
    let id = localStorage.getItem('purplesploit_session_id');
    if (!id) {
        id = 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        localStorage.setItem('purplesploit_session_id', id);
    }
    return id;
}

/**
 * Connect to WebSocket
 */
function connectWebSocket() {
    updateConnectionStatus('connecting', 'Connecting...');

    try {
        websocket = new WebSocket(`${WS_BASE}/ws/c2/${sessionId}`);

        websocket.onopen = () => {
            updateConnectionStatus('connected', 'Connected');
            connectionAttempts = 0;
            appendOutput('System', 'Connected to PurpleSploit C2 server', 'success');
        };

        websocket.onmessage = (event) => {
            const data = JSON.parse(event.data);
            handleWebSocketMessage(data);
        };

        websocket.onerror = (error) => {
            console.error('WebSocket error:', error);
            updateConnectionStatus('error', 'Connection Error');
        };

        websocket.onclose = () => {
            updateConnectionStatus('error', 'Disconnected');
            appendOutput('System', 'Disconnected from server', 'error');

            // Attempt reconnection
            if (connectionAttempts < MAX_CONNECTION_ATTEMPTS) {
                connectionAttempts++;
                const delay = Math.min(1000 * Math.pow(2, connectionAttempts), 30000);
                appendOutput('System', `Reconnecting in ${delay/1000}s... (attempt ${connectionAttempts}/${MAX_CONNECTION_ATTEMPTS})`, 'warning');
                setTimeout(connectWebSocket, delay);
            } else {
                appendOutput('System', 'Max reconnection attempts reached. Refresh page to retry.', 'error');
            }
        };
    } catch (error) {
        console.error('Failed to create WebSocket:', error);
        updateConnectionStatus('error', 'Connection Failed');
        // Fall back to HTTP API
        appendOutput('System', 'Using HTTP API fallback mode', 'warning');
    }
}

/**
 * Handle WebSocket messages
 */
function handleWebSocketMessage(data) {
    switch (data.type) {
        case 'connected':
            break;
        case 'output':
            appendCommandOutput(data.command, data.output);
            break;
        case 'error':
            appendOutput('Error', data.error, 'error');
            break;
        default:
            console.log('Unknown message type:', data);
    }
}

/**
 * Update connection status indicator
 */
function updateConnectionStatus(status, text) {
    statusDot.className = `status-dot status-${status}`;
    statusText.textContent = text;
}

/**
 * Handle keyboard input
 */
function handleKeyDown(e) {
    if (e.key === 'Enter') {
        e.preventDefault();
        const command = terminalInput.value.trim();
        if (command) {
            executeCommand(command);
            commandHistory.push(command);
            historyIndex = commandHistory.length;
            terminalInput.value = '';
        }
    } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        if (historyIndex > 0) {
            historyIndex--;
            terminalInput.value = commandHistory[historyIndex];
        }
    } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        if (historyIndex < commandHistory.length - 1) {
            historyIndex++;
            terminalInput.value = commandHistory[historyIndex];
        } else {
            historyIndex = commandHistory.length;
            terminalInput.value = '';
        }
    } else if (e.key === 'Tab') {
        e.preventDefault();
        autocompleteCommand();
    }
}

/**
 * Execute a command
 */
async function executeCommand(command) {
    // Show command in terminal
    appendCommand(command);

    // Check if WebSocket is connected
    if (websocket && websocket.readyState === WebSocket.OPEN) {
        // Send via WebSocket
        websocket.send(JSON.stringify({ command }));
    } else {
        // Fallback to HTTP API
        try {
            const response = await fetch(`${API_BASE}/api/c2/command`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ command, session_id: sessionId })
            });

            const data = await response.json();
            if (data.success) {
                appendOutput('', data.output);
            } else {
                appendOutput('Error', data.error || 'Command failed', 'error');
            }
        } catch (error) {
            appendOutput('Error', `Failed to execute command: ${error.message}`, 'error');
        }
    }

    // Update context after certain commands
    if (['use', 'target', 'back'].some(cmd => command.startsWith(cmd))) {
        setTimeout(updateContext, 500);
    }
}

/**
 * Execute a quick command from button
 */
function executeQuickCommand(command) {
    terminalInput.value = command;
    executeCommand(command);
}

/**
 * Append a command to terminal output
 */
function appendCommand(command) {
    const line = document.createElement('div');
    line.className = 'terminal-line terminal-command';
    line.innerHTML = `<span class="terminal-prompt-char">purplesploit &gt;</span> ${escapeHtml(command)}`;
    terminalOutput.appendChild(line);
    scrollToBottom();
}

/**
 * Append command output to terminal
 */
function appendCommandOutput(command, output) {
    appendOutput('', output);
}

/**
 * Append output to terminal
 */
function appendOutput(prefix, text, type = 'normal') {
    const line = document.createElement('div');
    line.className = `terminal-line terminal-output-text`;

    if (type !== 'normal') {
        line.classList.add(`terminal-${type}`);
    }

    const content = prefix ? `[${prefix}] ${text}` : text;
    line.textContent = content;

    terminalOutput.appendChild(line);
    scrollToBottom();
}

/**
 * Clear terminal
 */
function clearTerminal() {
    terminalOutput.innerHTML = '';
    appendOutput('System', 'Terminal cleared', 'info');
}

/**
 * Scroll terminal to bottom
 */
function scrollToBottom() {
    terminalOutput.scrollTop = terminalOutput.scrollHeight;
}

/**
 * Load modules from API
 */
async function loadModules() {
    try {
        const response = await fetch(`${API_BASE}/api/c2/modules`);
        modules = await response.json();
        displayModules(modules);
    } catch (error) {
        console.error('Failed to load modules:', error);
        moduleList.innerHTML = '<div class="empty">Failed to load modules</div>';
    }
}

/**
 * Display modules in sidebar
 */
function displayModules(modulesToDisplay) {
    // Group by category
    const grouped = modulesToDisplay.reduce((acc, mod) => {
        if (!acc[mod.category]) {
            acc[mod.category] = [];
        }
        acc[mod.category].push(mod);
        return acc;
    }, {});

    // Build HTML
    let html = '';
    Object.keys(grouped).sort().forEach(category => {
        html += `<div class="module-category">`;
        html += `<div class="category-header">${category.toUpperCase()}</div>`;
        grouped[category].forEach(mod => {
            html += `
                <div class="module-item" onclick="selectModule('${mod.path}')">
                    <span class="module-name">${escapeHtml(mod.name)}</span>
                    <span class="module-path">${escapeHtml(mod.path)}</span>
                </div>
            `;
        });
        html += `</div>`;
    });

    moduleList.innerHTML = html || '<div class="empty">No modules found</div>';
}

/**
 * Handle module search
 */
function handleModuleSearch(e) {
    const query = e.target.value.toLowerCase().trim();

    if (!query) {
        displayModules(modules);
        return;
    }

    const filtered = modules.filter(mod =>
        mod.name.toLowerCase().includes(query) ||
        mod.path.toLowerCase().includes(query) ||
        mod.category.toLowerCase().includes(query) ||
        mod.description.toLowerCase().includes(query)
    );

    displayModules(filtered);
}

/**
 * Select a module
 */
async function selectModule(modulePath) {
    try {
        const response = await fetch(`${API_BASE}/api/c2/module/${modulePath}`);
        const moduleInfo = await response.json();

        // Show module modal
        showModuleModal(moduleInfo);
    } catch (error) {
        appendOutput('Error', `Failed to load module info: ${error.message}`, 'error');
    }
}

/**
 * Show module info modal
 */
function showModuleModal(moduleInfo) {
    const modal = document.getElementById('module-modal');
    const modalBody = document.getElementById('modal-module-body');
    const modalTitle = document.getElementById('modal-module-name');

    modalTitle.textContent = moduleInfo.name;

    let html = `
        <div style="margin-bottom: 20px;">
            <p><strong>Path:</strong> <code>${escapeHtml(moduleInfo.path)}</code></p>
            <p><strong>Category:</strong> ${escapeHtml(moduleInfo.category)}</p>
            <p><strong>Description:</strong> ${escapeHtml(moduleInfo.description)}</p>
            <p><strong>Author:</strong> ${escapeHtml(moduleInfo.author)}</p>
        </div>

        <h3 style="margin-bottom: 10px; color: var(--accent-cyan);">Module Options</h3>
        <table style="width: 100%; border-collapse: collapse;">
            <thead>
                <tr style="border-bottom: 1px solid var(--border-color);">
                    <th style="text-align: left; padding: 10px; color: var(--text-secondary);">Option</th>
                    <th style="text-align: left; padding: 10px; color: var(--text-secondary);">Value</th>
                    <th style="text-align: left; padding: 10px; color: var(--text-secondary);">Required</th>
                    <th style="text-align: left; padding: 10px; color: var(--text-secondary);">Description</th>
                </tr>
            </thead>
            <tbody>
    `;

    Object.keys(moduleInfo.options).forEach(key => {
        const opt = moduleInfo.options[key];
        html += `
            <tr style="border-bottom: 1px solid var(--border-color);">
                <td style="padding: 10px; font-family: var(--font-mono); color: var(--accent-purple);">${escapeHtml(key)}</td>
                <td style="padding: 10px; font-family: var(--font-mono);">${escapeHtml(opt.value || '')}</td>
                <td style="padding: 10px;">${opt.required ? '<span style="color: var(--error);">Yes</span>' : 'No'}</td>
                <td style="padding: 10px; color: var(--text-secondary);">${escapeHtml(opt.description || '')}</td>
            </tr>
        `;
    });

    html += `
            </tbody>
        </table>
    `;

    modalBody.innerHTML = html;
    modal.classList.remove('hidden');

    // Store module path for use
    modal.dataset.modulePath = moduleInfo.path;
}

/**
 * Close module modal
 */
function closeModuleModal() {
    document.getElementById('module-modal').classList.add('hidden');
}

/**
 * Use module from modal
 */
function useModuleFromModal() {
    const modal = document.getElementById('module-modal');
    const modulePath = modal.dataset.modulePath;

    if (modulePath) {
        executeCommand(`use ${modulePath}`);
        closeModuleModal();
    }
}

/**
 * Update context information
 */
async function updateContext() {
    try {
        // Get current target
        const statsResponse = await fetch(`${API_BASE}/api/stats/overview`);
        const stats = await statsResponse.json();

        document.getElementById('stats-info').textContent =
            `${stats.total_targets}T ${stats.total_services}S`;

        // Update current module/target from session
        const sessionResponse = await fetch(`${API_BASE}/api/c2/session/${sessionId}`);
        if (sessionResponse.ok) {
            const session = await sessionResponse.json();

            if (session.current_module) {
                currentModuleDisplay.textContent = session.current_module;
                currentModuleDisplay.style.color = 'var(--success)';
            } else {
                currentModuleDisplay.textContent = 'None';
                currentModuleDisplay.style.color = 'var(--text-secondary)';
            }
        }
    } catch (error) {
        console.error('Failed to update context:', error);
    }
}

/**
 * Export session
 */
async function exportSession() {
    try {
        const response = await fetch(`${API_BASE}/api/c2/session/${sessionId}`);
        const session = await response.json();

        const dataStr = JSON.stringify(session, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(dataBlob);

        const link = document.createElement('a');
        link.href = url;
        link.download = `purplesploit_session_${sessionId}_${Date.now()}.json`;
        link.click();

        URL.revokeObjectURL(url);
        appendOutput('System', 'Session exported successfully', 'success');
    } catch (error) {
        appendOutput('Error', `Failed to export session: ${error.message}`, 'error');
    }
}

/**
 * Autocomplete command
 */
function autocompleteCommand() {
    const input = terminalInput.value;
    const words = input.split(' ');
    const lastWord = words[words.length - 1];

    // Simple autocomplete for commands
    const commands = ['help', 'search', 'use', 'show', 'set', 'run', 'back', 'target', 'targets', 'cred', 'creds', 'stats', 'clear'];

    if (words.length === 1) {
        const matches = commands.filter(cmd => cmd.startsWith(lastWord));
        if (matches.length === 1) {
            terminalInput.value = matches[0] + ' ';
        } else if (matches.length > 1) {
            appendOutput('', matches.join(', '), 'info');
        }
    }
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Refresh modules
 */
document.getElementById('refresh-modules')?.addEventListener('click', () => {
    appendOutput('System', 'Refreshing modules...', 'info');
    loadModules();
});

/* ============================================================================
   Target Management
   ============================================================================ */

async function showTargetManager() {
    const modal = document.getElementById('target-modal');
    modal.classList.remove('hidden');
    await loadTargetsList();
}

function closeTargetManager() {
    document.getElementById('target-modal').classList.add('hidden');
}

async function loadTargetsList() {
    const listContainer = document.getElementById('target-list');

    try {
        const response = await fetch(`${API_BASE}/api/targets`);
        const targets = await response.json();

        if (targets.length === 0) {
            listContainer.innerHTML = '<div class="empty">No targets configured</div>';
            return;
        }

        listContainer.innerHTML = targets.map(target => `
            <div class="entity-item">
                <div class="entity-info">
                    <div class="entity-name">${escapeHtml(target.name)}</div>
                    <div class="entity-details">${escapeHtml(target.ip)}</div>
                </div>
                <div class="entity-actions">
                    <button onclick="useTarget('${escapeHtml(target.ip)}')">Use</button>
                    <button class="delete" onclick="deleteTarget('${escapeHtml(target.name)}')">Delete</button>
                </div>
            </div>
        `).join('');
    } catch (error) {
        listContainer.innerHTML = '<div class="empty">Failed to load targets</div>';
        console.error('Failed to load targets:', error);
    }
}

async function addTarget(event) {
    event.preventDefault();

    const ip = document.getElementById('target-ip').value.trim();
    const name = document.getElementById('target-name').value.trim() || ip;

    try {
        // Execute via HTTP API to ensure we can wait for completion
        const response = await fetch(`${API_BASE}/api/c2/command`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                command: `target ${ip}`,
                session_id: sessionId
            })
        });

        const data = await response.json();

        if (data.success) {
            appendOutput('System', data.output, 'success');

            // Clear form
            document.getElementById('add-target-form').reset();

            // Reload list after successful addition
            await loadTargetsList();
        } else {
            appendOutput('Error', data.error || 'Failed to add target', 'error');
        }
    } catch (error) {
        appendOutput('Error', `Failed to add target: ${error.message}`, 'error');
    }
}

async function useTarget(ip) {
    executeCommand(`target ${ip}`);
    closeTargetManager();
}

async function deleteTarget(name) {
    if (!confirm(`Delete target ${name}?`)) return;

    try {
        await fetch(`${API_BASE}/api/targets/${name}`, { method: 'DELETE' });
        await loadTargetsList();
        appendOutput('System', `Target ${name} deleted`, 'success');
    } catch (error) {
        appendOutput('Error', `Failed to delete target: ${error.message}`, 'error');
    }
}

/* ============================================================================
   Credential Management
   ============================================================================ */

async function showCredentialManager() {
    const modal = document.getElementById('credential-modal');
    modal.classList.remove('hidden');
    await loadCredentialsList();
}

function closeCredentialManager() {
    document.getElementById('credential-modal').classList.add('hidden');
}

async function loadCredentialsList() {
    const listContainer = document.getElementById('credential-list');

    try {
        const response = await fetch(`${API_BASE}/api/credentials`);
        const credentials = await response.json();

        if (credentials.length === 0) {
            listContainer.innerHTML = '<div class="empty">No credentials configured</div>';
            return;
        }

        listContainer.innerHTML = credentials.map(cred => `
            <div class="entity-item">
                <div class="entity-info">
                    <div class="entity-name">${escapeHtml(cred.name)}</div>
                    <div class="entity-details">${escapeHtml(cred.username)}:${cred.password ? '***' : '[hash]'}</div>
                </div>
                <div class="entity-actions">
                    <button class="delete" onclick="deleteCredential('${escapeHtml(cred.name)}')">Delete</button>
                </div>
            </div>
        `).join('');
    } catch (error) {
        listContainer.innerHTML = '<div class="empty">Failed to load credentials</div>';
        console.error('Failed to load credentials:', error);
    }
}

async function addCredential(event) {
    event.preventDefault();

    const username = document.getElementById('cred-username').value.trim();
    const password = document.getElementById('cred-password').value;
    const domain = document.getElementById('cred-domain').value.trim();
    const hash = document.getElementById('cred-hash').value.trim();

    // Build command
    if (password) {
        executeCommand(`cred ${username}:${password}`);
    } else {
        // Use API for complex credentials
        try {
            await fetch(`${API_BASE}/api/credentials`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    name: username,
                    username: username,
                    domain: domain || null,
                    hash: hash || null
                })
            });
            appendOutput('System', `Credential ${username} added`, 'success');
        } catch (error) {
            appendOutput('Error', `Failed to add credential: ${error.message}`, 'error');
        }
    }

    // Clear form
    document.getElementById('add-credential-form').reset();

    // Reload list
    setTimeout(() => loadCredentialsList(), 500);
}

async function deleteCredential(name) {
    if (!confirm(`Delete credential ${name}?`)) return;

    try {
        await fetch(`${API_BASE}/api/credentials/${name}`, { method: 'DELETE' });
        await loadCredentialsList();
        appendOutput('System', `Credential ${name} deleted`, 'success');
    } catch (error) {
        appendOutput('Error', `Failed to delete credential: ${error.message}`, 'error');
    }
}

/* ============================================================================
   Module Configuration
   ============================================================================ */

let currentModuleInfo = null;

async function configureModuleFromModal() {
    // Get module info from modal
    const modal = document.getElementById('module-modal');
    const modulePath = modal.dataset.modulePath;

    if (!modulePath) return;

    try {
        const response = await fetch(`${API_BASE}/api/c2/module/${modulePath}`);
        currentModuleInfo = await response.json();

        showConfigModal(currentModuleInfo);
        closeModuleModal();
    } catch (error) {
        appendOutput('Error', `Failed to load module config: ${error.message}`, 'error');
    }
}

function showConfigModal(moduleInfo) {
    const modal = document.getElementById('config-modal');
    const modalTitle = document.getElementById('config-module-name');
    const optionsContainer = document.getElementById('config-options');

    modalTitle.textContent = `Configure: ${moduleInfo.name}`;

    // Build options form
    let html = '';
    Object.keys(moduleInfo.options).forEach(key => {
        const opt = moduleInfo.options[key];
        const required = opt.required ? 'required' : '';
        const requiredClass = opt.required ? 'required' : '';
        const requiredIndicator = opt.required ? '<span class="required-indicator">*</span>' : '';

        html += `
            <div class="config-option ${requiredClass}">
                <div class="option-label">
                    ${escapeHtml(key)}${requiredIndicator}
                </div>
                <div class="option-input">
                    <input
                        type="text"
                        name="${escapeHtml(key)}"
                        value="${escapeHtml(opt.value || '')}"
                        placeholder="${escapeHtml(opt.description || '')}"
                        ${required}
                        class="form-group input"
                    />
                </div>
                <div class="option-description">${escapeHtml(opt.description || '')}</div>
            </div>
        `;
    });

    optionsContainer.innerHTML = html;
    modal.classList.remove('hidden');
}

function closeConfigModal() {
    document.getElementById('config-modal').classList.add('hidden');
    currentModuleInfo = null;
}

async function runConfiguredModule(event) {
    event.preventDefault();

    if (!currentModuleInfo) {
        appendOutput('Error', 'No module loaded', 'error');
        return;
    }

    // Gather form values
    const formData = new FormData(event.target);
    const options = {};

    for (let [key, value] of formData.entries()) {
        if (value.trim()) {
            options[key] = value.trim();
        }
    }

    // Validate required options
    const requiredOptions = Object.keys(currentModuleInfo.options).filter(
        key => currentModuleInfo.options[key].required
    );

    const missingOptions = requiredOptions.filter(opt => !options[opt]);
    if (missingOptions.length > 0) {
        appendOutput('Error', `Missing required options: ${missingOptions.join(', ')}`, 'error');
        return;
    }

    closeConfigModal();

    // Show in terminal
    appendCommand(`use ${currentModuleInfo.path}`);
    appendOutput('', `Loaded module: ${currentModuleInfo.name}`);

    // Set options
    for (let [key, value] of Object.entries(options)) {
        appendCommand(`set ${key} ${value}`);
        appendOutput('', `Set ${key} => ${value}`);
    }

    // Execute module
    appendCommand('run');
    appendOutput('System', 'Executing module...', 'info');

    try {
        const response = await fetch(`${API_BASE}/api/c2/module/execute`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                module_path: currentModuleInfo.path,
                options: options,
                session_id: sessionId
            })
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`HTTP ${response.status}: ${errorText}`);
        }

        const result = await response.json();

        if (result.success) {
            appendOutput('Module Output', result.output, 'success');
            updateContext();  // Refresh context display
        } else {
            appendOutput('Error', result.error || 'Module execution failed', 'error');
        }
    } catch (error) {
        console.error('Module execution error:', error);
        appendOutput('Error', `Failed to execute module: ${error.message}`, 'error');
    }
}
