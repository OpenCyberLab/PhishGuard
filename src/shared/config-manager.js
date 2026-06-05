/**
 * Configuration Manager for Extension Settings
 * Handles loading and saving LLM server configuration
 */

/**
 * Get LLM settings from browser storage
 * @returns {Promise<object>}
 */
export async function getLlmSettings() {
  try {
    const result = await browser.storage.local.get('llmSettings');
    return result.llmSettings || getDefaultSettings();
  } catch (error) {
    console.error('PhishGuard: Failed to load settings:', error);
    return getDefaultSettings();
  }
}

/**
 * Save LLM settings to browser storage
 * @param {object} settings
 * @returns {Promise<boolean>}
 */
export async function saveLlmSettings(settings) {
  try {
    await browser.storage.local.set({ llmSettings: settings });
    return true;
  } catch (error) {
    console.error('PhishGuard: Failed to save settings:', error);
    return false;
  }
}

/**
 * Get default settings
 * @returns {object}
 */
function getDefaultSettings() {
  return {
    serverType: 'lm_studio',
    apiUrl: 'http://localhost:1234',
    port: 1234,
    selectedModel: 'local-model',
    apiFormat: 'openai',
    requestTimeout: 180,
    lastChecked: null,
    validated: false
  };
}
