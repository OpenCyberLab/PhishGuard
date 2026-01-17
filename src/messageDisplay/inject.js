/**
 * PhishGuard - Injected Panel
 */

(function() {
  'use strict';

  if (document.getElementById('phishguard-panel')) return;

  const panel = document.createElement('div');
  panel.id = 'phishguard-panel';
  panel.innerHTML = `
    <div class="pg-header">
      <div class="pg-brand">
        <svg viewBox="0 0 300 300" fill="none">
          <!-- PhishGuard logo - Full color version for light background -->
          <defs>
            <linearGradient id="panelShield" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" style="stop-color:#60a5fa;stop-opacity:1" />
              <stop offset="100%" style="stop-color:#3b82f6;stop-opacity:1" />
            </linearGradient>
          </defs>
          <!-- Shield with gradient -->
          <path d="M 150 30 
                   L 240 70 
                   L 240 160 
                   Q 240 225 150 270 
                   Q 60 225 60 160 
                   L 60 70 
                   Z" 
                fill="url(#panelShield)" 
                opacity="0.95"/>
          <!-- Inner shield detail -->
          <path d="M 150 45 
                   L 230 80 
                   L 230 160 
                   Q 230 218 150 258 
                   Q 70 218 70 160 
                   L 70 80 
                   Z" 
                fill="none" 
                stroke="rgba(255,255,255,0.4)"
                stroke-width="2"/>
          <!-- Fishing hook (red) -->
          <path d="M 205 100 
                   Q 205 88 213 88 
                   Q 221 88 221 100 
                   L 221 125 
                   Q 221 133 216 133 
                   Q 213 133 212 131 
                   L 215 138" 
                fill="none" 
                stroke="#ef4444" 
                stroke-width="5" 
                stroke-linecap="round"/>
          <!-- Fishing line -->
          <line x1="213" y1="88" x2="213" y2="55" 
                stroke="#ef4444" 
                stroke-width="2" 
                opacity="0.6"
                stroke-dasharray="4,4"/>
          <!-- Block line (white) -->
          <line x1="195" y1="90" x2="230" y2="145" 
                stroke="#ffffff" 
                stroke-width="11" 
                stroke-linecap="round"/>
          <!-- Check mark (white) -->
          <path d="M 100 160 L 130 190 L 185 120" 
                fill="none" 
                stroke="#ffffff" 
                stroke-width="13" 
                stroke-linecap="round" 
                stroke-linejoin="round"/>
        </svg>
        <span class="pg-brand-text">PhishGuard</span>
        <div class="pg-status loading" id="pgStatus"></div>
      </div>
      <div class="pg-header-right">
        <label class="pg-toggle-label">
          <span class="pg-toggle-text">Auto-scan</span>
          <input type="checkbox" id="pgAutoScan" class="pg-toggle-checkbox" />
          <span class="pg-toggle-slider"></span>
        </label>
      </div>
    </div>
    <div class="pg-body">
      <!-- Idle state (auto-scan off) -->
      <div class="pg-content-row" id="pgIdle" style="display:none">
        <div class="pg-content-left">
          <span class="pg-idle-text">🛡️ Auto-scan is off</span>
          <button class="pg-scan-btn" id="pgScanBtn">Scan Email</button>
        </div>
      </div>
      
      <!-- Loading state -->
      <div class="pg-content-row" id="pgLoading">
        <div class="pg-content-left">
          <div class="pg-spinner"></div>
          <span>Analyzing email...</span>
        </div>
      </div>
      
      <!-- Error state -->
      <div class="pg-content-row" id="pgError" style="display:none">
        <div class="pg-content-left">
          <span class="pg-error-text">⚠️ <span id="pgErrorMsg">Error</span></span>
          <button class="pg-retry" id="pgRetry">Retry</button>
          <button class="pg-settings-btn" id="pgOpenSettings">Open Settings</button>
        </div>
      </div>
      
      <!-- Result state (one line with all info) -->
      <div class="pg-content-row" id="pgResult" style="display:none">
        <div class="pg-content-left">
          <div class="pg-badge" id="pgBadge">--</div>
          <div class="pg-confidence" id="pgConf">--%</div>
          <div class="pg-auth">
            <div class="pg-auth-item"><span>SPF</span><b id="pgSpf" class="unknown">--</b></div>
            <div class="pg-auth-item"><span>DKIM</span><b id="pgDkim" class="unknown">--</b></div>
            <div class="pg-auth-item"><span>DMARC</span><b id="pgDmarc" class="unknown">--</b></div>
          </div>
        </div>
        <div class="pg-content-right">
          <button class="pg-link" id="pgToggle">Show details</button>
          <span class="pg-privacy">🔒 Private</span>
        </div>
      </div>
      
      <!-- Details (expandable) -->
      <div class="pg-details" id="pgDetails" style="display:none">
        <div class="pg-details-section">
          <strong>Analysis:</strong>
          <ul id="pgReasons"></ul>
        </div>
        <div class="pg-details-section">
          <strong>Recommended:</strong>
          <ul id="pgActions"></ul>
        </div>
        <div class="pg-disclaimer">
          ⚠️ AI analysis may not be 100% accurate. Use as a guide, not definitive proof. Report suspected phishing to IT.
        </div>
      </div>
    </div>
  `;

  document.body.insertBefore(panel, document.body.firstChild);

  const statusEl = document.getElementById('pgStatus');
  const idleEl = document.getElementById('pgIdle');
  const loadingEl = document.getElementById('pgLoading');
  const errorEl = document.getElementById('pgError');
  const errorMsg = document.getElementById('pgErrorMsg');
  const resultEl = document.getElementById('pgResult');
  const detailsEl = document.getElementById('pgDetails');
  const badgeEl = document.getElementById('pgBadge');
  const confEl = document.getElementById('pgConf');
  const autoScanCheckbox = document.getElementById('pgAutoScan');
  const scanBtn = document.getElementById('pgScanBtn');

  let lastTs = 0;
  let detailsOpen = false;
  let hasResult = false;
  let autoScanEnabled = true;

  // Load auto-scan preference
  async function loadAutoScanPreference() {
    try {
      const stored = await browser.storage.local.get('autoScanEnabled');
      autoScanEnabled = stored.autoScanEnabled !== false; // Default to true
      if (autoScanCheckbox) {
        autoScanCheckbox.checked = autoScanEnabled;
      }
    } catch (e) {
      console.error('PhishGuard: Failed to load auto-scan preference:', e);
    }
  }

  // Event listeners
  document.getElementById('pgToggle').onclick = () => {
    detailsOpen = !detailsOpen;
    detailsEl.style.display = detailsOpen ? 'block' : 'none';
    document.getElementById('pgToggle').textContent = detailsOpen ? 'Hide details' : 'Show details';
  };

  document.getElementById('pgRetry').onclick = () => {
    browser.runtime.sendMessage({ action: 'scanCurrentMessage' }).catch(() => {});
    showLoading();
  };

  document.getElementById('pgOpenSettings').onclick = () => {
    browser.runtime.sendMessage({ action: 'openSettings' });
  };

  if (scanBtn) {
    scanBtn.onclick = () => {
      browser.runtime.sendMessage({ action: 'scanCurrentMessage' }).catch(() => {});
      showLoading();
    };
  }

  if (autoScanCheckbox) {
    autoScanCheckbox.onchange = async (e) => {
      autoScanEnabled = e.target.checked;
      
      // Save preference
      try {
        await browser.storage.local.set({ autoScanEnabled });
        
        // If enabling and currently idle, trigger scan
        if (autoScanEnabled && idleEl.style.display !== 'none') {
          requestScan();
        }
      } catch (e) {
        console.error('PhishGuard: Failed to save auto-scan preference:', e);
      }
    };
  }

  // Listen for storage changes to sync settings across popup and panel
  browser.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes.autoScanEnabled) {
      const newValue = changes.autoScanEnabled.newValue;
      autoScanEnabled = newValue !== false;
      if (autoScanCheckbox) {
        autoScanCheckbox.checked = autoScanEnabled;
      }
      
      // If enabling and currently idle, trigger scan
      if (autoScanEnabled && idleEl.style.display !== 'none') {
        requestScan();
      }
    }
  });

  // Listen for toggle display message from background script
  browser.runtime.onMessage.addListener((message) => {
    if (message.action === 'toggleDisplay') {
      // Toggle panel visibility
      if (panel.style.display === 'none') {
        panel.style.display = 'block';
      } else {
        panel.style.display = 'none';
      }
    }
  });

  function showIdle() {
    idleEl.style.display = 'flex';
    loadingEl.style.display = 'none';
    errorEl.style.display = 'none';
    resultEl.style.display = 'none';
    detailsEl.style.display = 'none';
    statusEl.className = 'pg-status idle';
  }

  function showLoading() {
    idleEl.style.display = 'none';
    loadingEl.style.display = 'flex';
    errorEl.style.display = 'none';
    resultEl.style.display = 'none';
    detailsEl.style.display = 'none';
    statusEl.className = 'pg-status loading';
  }

  function showError(msg) {
    errorMsg.textContent = msg || 'Analysis failed';
    idleEl.style.display = 'none';
    loadingEl.style.display = 'none';
    errorEl.style.display = 'flex';
    resultEl.style.display = 'none';
    detailsEl.style.display = 'none';
    statusEl.className = 'pg-status error';
  }

  function showResult(result, parsed) {
    hasResult = true;
    const isBad = result.verdict === 'malicious';
    
    badgeEl.textContent = isBad ? '⚠️ MALICIOUS' : '✅ SAFE';
    badgeEl.className = 'pg-badge ' + (isBad ? 'danger' : 'safe');
    confEl.textContent = result.confidence + '%';
    confEl.style.color = isBad ? '#dc2626' : '#059669';

    const auth = parsed?.authentication || {};
    setAuth('pgSpf', auth.spf?.status);
    setAuth('pgDkim', auth.dkim?.status);
    setAuth('pgDmarc', auth.dmarc?.status);

    document.getElementById('pgReasons').innerHTML = 
      (result.reasons || []).slice(0, 4).map(r => `<li>${esc(r)}</li>`).join('') || '<li>No issues</li>';
    document.getElementById('pgActions').innerHTML = 
      (result.next_steps || []).slice(0, 3).map(a => `<li>${esc(a)}</li>`).join('') || '<li>None</li>';

    idleEl.style.display = 'none';
    loadingEl.style.display = 'none';
    errorEl.style.display = 'none';
    resultEl.style.display = 'flex';
    // Details stay hidden until user clicks
    statusEl.className = 'pg-status success';
  }

  function setAuth(id, s) {
    const el = document.getElementById(id);
    s = (s || 'unknown').toLowerCase();
    el.textContent = s.toUpperCase();
    el.className = s === 'pass' ? 'pass' : s === 'fail' ? 'fail' : 'unknown';
  }

  function esc(t) {
    const d = document.createElement('div');
    d.textContent = t || '';
    return d.innerHTML;
  }

  function process(state) {
    if (!state) return;
    
    // Skip if we already have a result and this is an older/same timestamp
    if (state.timestamp && state.timestamp <= lastTs) return;
    lastTs = state.timestamp || Date.now();

    if (state.state === 'success' && state.result) {
      showResult(state.result, state.parsedMessage);
    } else if (state.state === 'error') {
      showError(state.error);
    } else if (state.state === 'loading') {
      showLoading();
    } else if (state.state === 'idle') {
      // Only show idle UI if auto-scan is disabled
      if (!autoScanEnabled) {
        showIdle();
      } else {
        showLoading();
      }
    }
  }

  async function poll() {
    try {
      const d = await browser.storage.local.get('phishguardState');
      if (d?.phishguardState) process(d.phishguardState);
    } catch (e) {
      // Silently ignore poll errors
    }
  }

  // Request a scan when panel loads (in case we missed the event)
  async function requestScan() {
    try {
      const response = await browser.runtime.sendMessage({ action: 'scanCurrentMessage' });
      
      if (response && response.status === 'no_message') {
        // Background has no message yet. Will retry when polling detects a change.
        setTimeout(() => {
          requestScan();
        }, 1000);
      }
    } catch (e) {
      console.error('PhishGuard: Failed to request scan:', e.message);
    }
  }

  // Initialize
  async function initialize() {
    // Load auto-scan preference first
    await loadAutoScanPreference();
    
    if (autoScanEnabled) {
      showLoading();
      requestScan();
    } else {
      showIdle();
    }
    
    // Start polling
    setInterval(poll, 300);
  }
  
  initialize();
})();
