
// ========== SCAN MANAGEMENT ==========
async function refreshScans() {
    await loadActiveScans();
    await loadCompletedScans();
}

async function loadActiveScans() {
    try {
        const res = await fetch(`${API_BASE}/api/scans/active`);
        const data = await res.json();

        // Filter by current project
        const projectScans = data.scans.filter(s => (s.project || 'Default') === state.currentProject);

        const container = document.getElementById('active-scans-list');

        if (projectScans.length === 0) {
            container.innerHTML = '<div class="empty-state"><p>No active scans</p></div>';
            return;
        }

        container.innerHTML = projectScans.map(scan => `
            <div class="scan-item" style="padding: 1rem; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center;">
                <div style="flex: 1;">
                    <div style="font-weight: 600; color: var(--accent-cyan);">${scan.id}</div>
                    <div style="font-size: 0.875rem; color: var(--text-secondary); margin-top: 0.25rem;">
                        Status: <span style="color: ${scan.status === 'paused' ? 'orange' : '#00ff64'};">${scan.status}</span> 
                        | Progress: ${scan.progress || 0}%
                        | ${scan.message || '...'}
                    </div>
                </div>
                <div style="display: flex; gap: 0.5rem;">
                    ${scan.status === 'paused'
                ? `<button class="btn btn-sm" onclick="resumeScan('${scan.id}')" style="background: rgba(0,255,100,0.2); color: #00ff64; border: 1px solid #00ff64;">▶ Resume</button>`
                : `<button class="btn btn-sm" onclick="pauseScan('${scan.id}')" style="background: rgba(255,165,0,0.2); color: orange; border: 1px solid orange;">⏸ Pause</button>`
            }
                    <button class="btn btn-sm btn-primary" onclick="viewScan('${scan.id}')">👁 View</button>
                </div>
            </div>
        `).join('');

    } catch (e) {
        console.error("Failed to load active scans:", e);
    }
}

async function loadCompletedScans() {
    try {
        const res = await fetch(`${API_BASE}/api/scans`);
        const data = await res.json();

        // Filter by current project and exclude running/paused
        const projectScans = data.scans.filter(s =>
            (s.project || 'Default') === state.currentProject &&
            s.status !== 'running' &&
            s.status !== 'paused'
        );

        state.allScans = projectScans; // Store for filtering
        renderCompletedScans(projectScans);

    } catch (e) {
        console.error("Failed to load completed scans:", e);
    }
}

function renderCompletedScans(scans) {
    const container = document.getElementById('completed-scans-list');

    if (scans.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No completed scans yet</p></div>';
        return;
    }

    container.innerHTML = scans.map(scan => {
        const date = scan.completed_at ? new Date(scan.completed_at).toLocaleString() : 'Unknown';
        const statusColor = scan.status === 'completed' ? '#00ff64' : (scan.status === 'failed' ? '#ff4444' : 'orange');

        return `
            <div class="scan-item" style="padding: 1rem; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; cursor: pointer;" onclick="viewScan('${scan.id}')">
                <div style="flex: 1;">
                    <div style="font-weight: 600;">${scan.target_domain || scan.id}</div>
                    <div style="font-size: 0.875rem; color: var(--text-secondary); margin-top: 0.25rem;">
                        <span style="color: ${statusColor};">●</span> ${scan.status} 
                        | ${date}
                        | Bugs: ${scan.total_bugs || 0}
                        | Subdomains: ${scan.total_subdomains || 0}
                    </div>
                </div>
                <button class="btn btn-sm btn-primary" onclick="event.stopPropagation(); viewScan('${scan.id}')">View Results</button>
            </div>
        `;
    }).join('');
}

function filterScanHistory(query) {
    if (!state.allScans) return;

    const filtered = state.allScans.filter(s =>
        s.id.toLowerCase().includes(query.toLowerCase()) ||
        (s.target_domain && s.target_domain.toLowerCase().includes(query.toLowerCase()))
    );

    renderCompletedScans(filtered);
}

async function viewScan(scanId) {
    state.currentScan = scanId;

    try {
        await loadScanResults(scanId);
        showPage('bugs'); // Switch to bugs view after loading
        showToast(`Loaded scan: ${scanId}`, 'success');
    } catch (e) {
        showToast(`Failed to load scan: ${e.message}`, 'error');
    }
}

async function pauseScan(scanId) {
    try {
        await fetch(`${API_BASE}/api/scan/${scanId}/pause`, { method: 'POST' });
        showToast('⏸ Scan paused', 'info');
        setTimeout(refreshScans, 500);
    } catch (e) {
        showToast('Failed to pause', 'error');
    }
}

async function resumeScan(scanId) {
    try {
        await fetch(`${API_BASE}/api/scan/${scanId}/resume`, { method: 'POST' });
        showToast('▶ Scan resumed', 'success');
        setTimeout(refreshScans, 500);
    } catch (e) {
        showToast('Failed to resume', 'error');
    }
}
