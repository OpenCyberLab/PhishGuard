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
        <svg viewBox="0 50 155 160" fill="none" xmlns="http://www.w3.org/2000/svg">
          <defs>
            <radialGradient id="shieldGrad" cx="77" cy="130" r="80" gradientUnits="userSpaceOnUse">
              <stop offset="0" stop-color="#37a1ee"/>
              <stop offset="1" stop-color="#2418c7"/>
            </radialGradient>
          </defs>
          <!-- Shield fill -->
          <path d="M8.5 75.3c24-2.9 47-7.9 68.3-15.5 22 7 44.3 13 68.3 16.2 8.9 79.9-26.4 109.5-68.3 131.4C18.6 177.5 1.6 137 8.5 75.3z" fill="url(#shieldGrad)" opacity="0.98"/>
          <!-- Shield white border -->
          <path d="M15 80.8c21.7-2.6 42.5-7.2 61.8-14 19.9 6.4 40.2 12 61.9 14.9 8 72-24.3 98.6-61.9 118.5-52.7-27-68-63.3-61.8-119.4z" fill="none" stroke="#ffffff" stroke-width="1" stroke-linecap="round" stroke-linejoin="round"/>
          <!-- Email envelope body -->
          <rect x="52" y="120" width="49" height="34" rx="6" fill="#f7da10"/>
          <!-- Email envelope flap triangle -->
          <path d="M84.3 120.5h10.2l-5.1 5.5-12 3.8z" fill="#f7da10"/>
          <!-- Email envelope lines -->
          <g stroke="#ffffff" stroke-width="1.2" stroke-linecap="round" fill="none">
            <path d="M64.6 128.8l11.5 8.7 11.4-8.6"/>
            <path d="M64.5 142.9l9.3-7 2.2 1.7 2.2-1.6 9.4 7.1"/>
          </g>
          <!-- Fishing hook -->
          <path d="M91.4 109.8c-.1 0-.3.1-.3.2-.5.9.9 2.4 1.1 3 .9 2.4 3.1 8.8 3.2 12.6.1 2-.2 4.4-1.2 5.8-1.6 1.7-4.6 2.4-6.8 1.5-1.4-.6-2.1-2.1-2.6-3.6.4-.2 1.4.7 1.9.7l-2.3-1.8v-.1c-.5-1.4-.5-4.5-.5-4.5s-.7 3.3-.3 4.9c.6 2.3 1.5 5.2 3.7 6 2.7 1 6.3-.2 8.2-2.3 1.7-1.8 1.6-4.7 1.5-7.1-.2-3.8-2.7-10.2-3.7-12.5-.2-.5-.2-2.3-1.1-2.8-.2-.1-.5-.1-.7 0z" fill="#241f1c"/>
          <!-- Hook line (red) -->
          <path d="M92.3 82.2v31.1l1.6.5V82.2z" fill="#de0000"/>
          <!-- Red circle (no phishing) -->
          <circle cx="78.5" cy="126.2" r="47.3" fill="none" stroke="#ff0000" stroke-width="7.2" stroke-linecap="round"/>
          <!-- Red diagonal slash -->
          <path d="M44.2 95l66.9 63.1" fill="none" stroke="#ff0000" stroke-width="7.2" stroke-linecap="round"/>
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

    const reasonsEl = document.getElementById('pgReasons');
    reasonsEl.textContent = '';
    const reasons = (result.reasons || []).slice(0, 4);
    if (reasons.length === 0) {
      const li = document.createElement('li');
      li.textContent = 'No issues';
      reasonsEl.appendChild(li);
    } else {
      reasons.forEach(r => {
        const li = document.createElement('li');
        li.textContent = r;
        reasonsEl.appendChild(li);
      });
    }

    const actionsEl = document.getElementById('pgActions');
    actionsEl.textContent = '';
    const actions = (result.next_steps || []).slice(0, 3);
    if (actions.length === 0) {
      const li = document.createElement('li');
      li.textContent = 'None';
      actionsEl.appendChild(li);
    } else {
      actions.forEach(a => {
        const li = document.createElement('li');
        li.textContent = a;
        actionsEl.appendChild(li);
      });
    }

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
