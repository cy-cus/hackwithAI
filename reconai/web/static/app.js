/**
 * ReconLLM Web UI - Main JavaScript
 */

// Global state
let currentScanId = null;
let scanRunning = false;
let websocket = null;

// Warn before leaving during scan
window.addEventListener('beforeunload', (e) => {
    if (scanRunning) {
        const message = '⚠️ Scan in progress! If you leave, you will lose the progress view.\n\nThe scan will continue in the background, but you won\'t see updates.\n\nAre you sure you want to leave?';
        e.preventDefault();
        e.returnValue = message;
        return message;
    }
});

// Check for running scans on page load
window.addEventListener('load', async () => {
    // Check if there's a scan ID in sessionStorage
    const savedScanId = sessionStorage.getItem('currentScanId');
    if (savedScanId) {
        // Try to reconnect to the scan
        await reconnectToScan(savedScanId);
    }
});

/**
 * Reconnect to a running scan
 */
async function reconnectToScan(scanId) {
    try {
        const response = await fetch(`/api/scan/${scanId}/status`);
        const data = await response.json();
        
        if (data.status === 'running') {
            // Scan is still running, reconnect
            console.log('Reconnecting to scan:', scanId);
            currentScanId = scanId;
            scanRunning = true;
            
            // Show progress panel
            document.getElementById('progressPanel').classList.remove('hidden');
            document.getElementById('emptyState').classList.add('hidden');
            
            // Update progress
            updateProgress(data.progress, data.message);
            
            // Reconnect WebSocket
            connectWebSocket(scanId);
            
            // Show notification
            showNotification('Reconnected to running scan', 'info');
        } else if (data.status === 'completed') {
            // Scan completed while we were away
            showNotification('Previous scan completed', 'success');
            loadResults(scanId);
        }
    } catch (error) {
        console.error('Error reconnecting to scan:', error);
        sessionStorage.removeItem('currentScanId');
    }
}

/**
 * Start a new scan
 */
async function startScan(target, model, options = {}) {
    try {
        const response = await fetch('/api/scan/start', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                target,
                model,
                skip_llm: options.skipLlm || false,
                js_size_filter: options.jsSizeFilter || 'medium'
            })
        });
        
        const data = await response.json();
        
        if (data.scan_id) {
            currentScanId = data.scan_id;
            scanRunning = true;
            
            // Save to sessionStorage for reconnection
            sessionStorage.setItem('currentScanId', data.scan_id);
            
            // Show progress
            document.getElementById('progressPanel').classList.remove('hidden');
            document.getElementById('emptyState').classList.add('hidden');
            
            // Connect WebSocket
            connectWebSocket(data.scan_id);
        }
    } catch (error) {
        console.error('Error starting scan:', error);
        alert('Failed to start scan: ' + error.message);
    }
}

/**
 * Connect to scan WebSocket
 */
function connectWebSocket(scanId) {
    const wsUrl = `ws://${window.location.host}/ws/scan/${scanId}`;
    
    websocket = new WebSocket(wsUrl);
    
    websocket.onopen = () => {
        console.log('WebSocket connected');
    };
    
    websocket.onmessage = (event) => {
        const data = JSON.parse(event.data);
        
        // Update progress bar
        updateProgress(data.progress, data.message);
        
        // Check if complete
        if (data.status === 'completed') {
            scanRunning = false;
            sessionStorage.removeItem('currentScanId');
            websocket.close();
            loadResults(scanId);
        } else if (data.status === 'failed') {
            scanRunning = false;
            sessionStorage.removeItem('currentScanId');
            websocket.close();
            showNotification('Scan failed: ' + data.message, 'error');
        }
    };
    
    websocket.onerror = (error) => {
        console.error('WebSocket error:', error);
    };
    
    websocket.onclose = () => {
        console.log('WebSocket closed');
        // Try to reconnect if scan is still running
        if (scanRunning) {
            setTimeout(() => {
                console.log('Attempting to reconnect...');
                connectWebSocket(scanId);
            }, 5000);
        }
    };
}

/**
 * Update progress display
 */
function updateProgress(progress, message) {
    const progressBar = document.getElementById('progressBar');
    const progressText = document.getElementById('progressText');
    
    if (progressBar) {
        progressBar.style.width = progress + '%';
        progressBar.textContent = progress + '%';
    }
    
    if (progressText) {
        progressText.textContent = message;
    }
}

/**
 * Load scan results
 */
async function loadResults(scanId) {
    try {
        const response = await fetch(`/api/scan/${scanId}/result`);
        const data = await response.json();
        
        // Update UI with results
        displayResults(data.result);
        
        // Hide progress, show results
        document.getElementById('progressPanel').classList.add('hidden');
        document.getElementById('resultsPanel').classList.remove('hidden');
        
    } catch (error) {
        console.error('Error loading results:', error);
        alert('Failed to load results');
    }
}

/**
 * Display results in UI
 */
function displayResults(result) {
    // Update stats
    document.getElementById('stat-subdomains').textContent = result.total_subdomains || 0;
    document.getElementById('stat-endpoints').textContent = result.total_endpoints || 0;
    document.getElementById('stat-js').textContent = result.total_js_files || 0;
    document.getElementById('stat-secrets').textContent = result.total_secrets || 0;
    
    // Display findings
    displayFindings(result.findings || []);
    
    // Display secrets
    displaySecrets(result.js_analysis?.secrets || []);
    
    // Display endpoints
    displayEndpoints(result.endpoints || []);
}

/**
 * Show notification
 */
function showNotification(message, type = 'info') {
    // Simple alert for now, can be enhanced with toast notifications
    console.log(`[${type.toUpperCase()}] ${message}`);
    
    // You can add a toast library here for better UX
    if (type === 'error') {
        alert(message);
    }
}

// Export functions for use in HTML
window.startScan = startScan;
window.reconnectToScan = reconnectToScan;
