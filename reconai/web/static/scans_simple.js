// BULLETPROOF SCAN DISPLAY - STRIPPED DOWN VERSION THAT WORKS

let scanPoller = null;

async function loadActiveScans() {
    console.log("Loading active scans...");
    try {
        const res = await fetch(`${API_BASE}/api/scans/active`);
        console.log("Active scans response:", res.status);
        const data = await res.json();
        console.log("Active scans data:", data);

        const container = document.getElementById('active-scans-list');
        if (!container) {
            console.error("CONTAINER NOT FOUND: active-scans-list");
            return;
        }

        const scans = data.scans || [];
        console.log(`Found ${scans.length} active scans`);

        if (scans.length === 0) {
            container.innerHTML = '<div style="padding: 2rem; text-align: center; color: white;">No active scans right now</div>';
            return;
        }

        // SIMPLE DISPLAY
        container.innerHTML = scans.map(scan => `
            <div style="padding: 1.5rem; margin-bottom: 1rem; background: rgba(0,255,100,0.1); border: 2px solid #00ff64; border-radius: 8px;">
                <div style="font-size: 1.5rem; font-weight: bold; color: #00ff64; margin-bottom: 0.5rem;">
                    ${scan.target || scan.id}
                </div>
                <div style="color: white; margin-bottom: 0.5rem;">
                    Status: <strong>${scan.status}</strong> | Progress: <strong>${scan.progress || 0}%</strong>
                </div>
                <div style="color: #ccc;">
                    ${scan.message || 'Running...'}
                </div>
                ${scan.current_tool ? `<div style="color: cyan; margin-top: 0.5rem;">🔧 Running: ${scan.current_tool}</div>` : ''}
                ${scan.stats ? `
                    <div style="margin-top: 1rem; display: flex; gap: 1rem; flex-wrap: wrap;">
                        ${scan.stats.subdomains_found ? `<span style="padding: 0.5rem 1rem; background: rgba(0,255,200,0.2); border-radius: 4px;">📡 ${scan.stats.subdomains_found} subdomains</span>` : ''}
                        ${scan.stats.live_hosts ? `<span style="padding: 0.5rem 1rem; background: rgba(0,255,100,0.2); border-radius: 4px;">✅ ${scan.stats.live_hosts} live hosts</span>` : ''}
                        ${scan.stats.endpoints_found ? `<span style="padding: 0.5rem 1rem; background: rgba(255,165,0,0.2); border-radius: 4px;">🔗 ${scan.stats.endpoints_found} endpoints</span>` : ''}
                    </div>
                ` : ''}
            </div>
        `).join('');

        // Poll again in 2 seconds
        if (scanPoller) clearTimeout(scanPoller);
        scanPoller = setTimeout(loadActiveScans, 2000);

    } catch (err) {
        console.error("ERROR loading active scans:", err);
        const container = document.getElementById('active-scans-list');
        if (container) {
            container.innerHTML = `<div style="padding: 2rem; color: red;">ERROR: ${err.message}</div>`;
        }
    }
}

async function loadCompletedScans() {
    console.log("Loading completed scans...");
    try {
        const res = await fetch(`${API_BASE}/api/scans`);
        console.log("Completed scans response:", res.status);
        const data = await res.json();
        console.log("Completed scans data:", data);

        const container = document.getElementById('completed-scans-list');
        if (!container) {
            console.error("CONTAINER NOT FOUND: completed-scans-list");
            return;
        }

        const scans = (data.scans || []).filter(s => s.status !== 'running' && s.status !== 'paused');
        console.log(`Found ${scans.length} completed scans`);

        if (scans.length === 0) {
            container.innerHTML = '<div style="padding: 2rem; text-align: center; color: white;">No completed scans yet</div>';
            return;
        }

        // SIMPLE DISPLAY
        container.innerHTML = scans.map(scan => `
            <div style="padding: 1.5rem; margin-bottom: 1rem; background: rgba(255,255,255,0.05); border: 1px solid #444; border-radius: 8px; cursor: pointer;" onclick="viewScan('${scan.id}')">
                <div style="font-size: 1.25rem; font-weight: bold; color: white; margin-bottom: 0.5rem;">
                    ${scan.target || scan.id}
                </div>
                <div style="color: #ccc;">
                    Status: <span style="color: ${scan.status === 'completed' ? '#00ff64' : '#ff4444'}">${scan.status}</span>
                </div>
                ${scan.total_bugs ? `<div style="color: #ff4444; margin-top: 0.5rem;">🐛 ${scan.total_bugs} bugs found</div>` : ''}
            </div>
        `).join('');

    } catch (err) {
        console.error("ERROR loading completed scans:", err);
        const container = document.getElementById('completed-scans-list');
        if (container) {
            container.innerHTML = `<div style="padding: 2rem; color: red;">ERROR: ${err.message}</div>`;
        }
    }
}

async function refreshScans() {
    console.log("REFRESHING ALL SCANS");
    await loadActiveScans();
    await loadCompletedScans();
}

// Call on page load
console.log("INITIALIZING SCAN DISPLAY");
setTimeout(refreshScans, 1000);
