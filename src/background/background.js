/**
 * PhishGuard - Background Script for Thunderbird
 */

import { scanWithLlm, testLlmConnection } from '../shared/api.js';
import { parseThunderbirdMessage } from '../shared/parsing.js';
import { getCachedScan, setCachedScan } from '../shared/state.js';

// State
let currentState = {
  state: 'idle',
  messageId: null,
  parsedMessage: null,
  result: null,
  error: null
};

let lastDisplayedMessage = null;

// Track current scan to cancel outdated requests
let currentScanId = 0;

/**
 * Save state to storage
 */
async function saveState() {
  const data = { ...currentState, timestamp: Date.now() };
  await messenger.storage.local.set({ phishguardState: data });
}

/**
 * Get message data
 */
async function getMessageData(messageId) {
  const info = await messenger.messages.get(messageId);
  const full = await messenger.messages.getFull(messageId);
  let textParts = [], attachments = [];
  try { textParts = await messenger.messages.listInlineTextParts(messageId); } catch(e) {}
  try { attachments = await messenger.messages.listAttachments(messageId); } catch(e) {}
  return { messageInfo: info, fullMessage: full, textParts, attachments };
}

/**
 * Scan message
 */
async function scanMessage(messageId, force = false) {
  // Increment scan ID to invalidate any in-flight requests
  const thisScanId = ++currentScanId;
  
  // Check cache first
  if (!force) {
    const cached = getCachedScan(String(messageId));
    if (cached) {
      // Verify this is still the current scan before updating state
      if (thisScanId !== currentScanId) return;
      
      const data = await getMessageData(messageId);
      const parsed = parseThunderbirdMessage(data);
      currentState = { state: 'success', messageId, parsedMessage: parsed, result: cached, error: null };
      await saveState();
      return;
    }
  }
  
  // Set loading state with current messageId
  currentState = { state: 'loading', messageId, parsedMessage: null, result: null, error: null };
  await saveState();
  
  try {
    const data = await getMessageData(messageId);
    
    // Check if this scan is still current before continuing
    if (thisScanId !== currentScanId) {
      return; // A newer scan has been initiated, abort this one
    }
    
    const parsed = parseThunderbirdMessage(data);
    const result = await scanWithLlm(parsed);
    
    // Check again after LLM call - this is the critical check
    if (thisScanId !== currentScanId) {
      return; // A newer scan has been initiated, discard this result
    }
    
    setCachedScan(String(messageId), result);
    currentState = { state: 'success', messageId, parsedMessage: parsed, result, error: null };
    await saveState();
  } catch (err) {
    // Only update error state if this is still the current scan
    if (thisScanId !== currentScanId) {
      return;
    }
    
    console.error('PhishGuard: Scan error:', err);
    currentState = { state: 'error', messageId, parsedMessage: null, result: null, error: err.message || String(err) };
    await saveState();
  }
}

// Register script on load
if (messenger.messageDisplayScripts) {
  messenger.messageDisplayScripts.register({
    js: [{ file: "/src/messageDisplay/inject.js" }],
    css: [{ file: "/src/messageDisplay/inject.css" }]
  }).catch(err => {
    console.error('PhishGuard: Failed to register messageDisplayScripts:', err);
  });
} else {
  console.error('PhishGuard: messageDisplayScripts API not available');
}

// Listen for message display
messenger.messageDisplay.onMessagesDisplayed.addListener(async (tab, messages) => {
  // Try different possible structures
  let messageList = null;
  
  if (Array.isArray(messages) && messages.length > 0) {
    messageList = messages;
  } else if (messages?.messages && Array.isArray(messages.messages) && messages.messages.length > 0) {
    messageList = messages.messages;
  }
  
  if (messageList && messageList.length > 0) {
    const msg = messageList[0];
    lastDisplayedMessage = msg;
    
    // Check auto-scan setting before scanning
    const stored = await messenger.storage.local.get('autoScanEnabled');
    const autoScanEnabled = stored.autoScanEnabled !== false; // Default to true
    
    if (autoScanEnabled) {
      scanMessage(msg.id);
    } else {
      // Parse headers for quick manual scan later
      try {
        const data = await getMessageData(msg.id);
        const parsed = parseThunderbirdMessage(data);
        currentState = { state: 'idle', messageId: msg.id, parsedMessage: parsed, result: null, error: null };
        await saveState();
      } catch (err) {
        currentState = { state: 'idle', messageId: msg.id, parsedMessage: null, result: null, error: null };
        await saveState();
      }
    }
  }
});

// Listen for button clicks (message_display_action)
if (messenger.messageDisplayAction && messenger.messageDisplayAction.onClicked) {
  messenger.messageDisplayAction.onClicked.addListener(async (tab) => {
    // Get the currently displayed message
    if (lastDisplayedMessage) {
      // Send message to content script to show/toggle the inline display
      try {
        await messenger.tabs.sendMessage(tab.id, {
          action: 'toggleDisplay'
        });
        
        // Start the scan
        scanMessage(lastDisplayedMessage.id, true);
      } catch (err) {
        console.error('PhishGuard: Failed to send message to content script:', err);
      }
    }
  });
}

// Handle messages
messenger.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'getState') {
    sendResponse(currentState);
    return false;
  }
  if (message.action === 'testConnection') {
    testLlmConnection().then(result => sendResponse(result));
    return true;
  }
  if (message.action === 'openSettings') {
    messenger.runtime.openOptionsPage();
    sendResponse({ status: 'opened' });
    return false;
  }
  if (message.action === 'scanCurrentMessage') {
    if (lastDisplayedMessage) {
      scanMessage(lastDisplayedMessage.id, true);
      sendResponse({ status: 'scanning', messageId: lastDisplayedMessage.id });
    } else {
      sendResponse({ status: 'no_message' });
    }
    return false;
  }
  if (message.action === 'scanMessage' && message.messageId) {
    messenger.messages.get(message.messageId).then(msg => {
      lastDisplayedMessage = msg;
      scanMessage(message.messageId, true);
      sendResponse({ status: 'scanning', messageId: message.messageId });
    }).catch(err => {
      console.error('PhishGuard: Failed to get message:', err);
      sendResponse({ status: 'error', error: err.message });
    });
    return true;
  }
  if (message.action === 'getCurrentMessage' && lastDisplayedMessage) {
    sendResponse({ messageId: lastDisplayedMessage.id, subject: lastDisplayedMessage.subject, author: lastDisplayedMessage.author });
    return false;
  }
  if (message.action === 'getFullMessage' && message.messageId) {
    getMessageData(message.messageId).then(data => sendResponse(data));
    return true;
  }
  
  sendResponse(null);
  return false;
});

// Save initial state
saveState();
