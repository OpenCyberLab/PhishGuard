/**
 * PhishGuard Options Page JavaScript
 */

import { getLlmSettings, saveLlmSettings } from '../shared/config-manager.js';
import { getAvailableModels, testLlmConnection } from '../shared/api.js';

// Server type to default settings mapping
const SERVER_DEFAULTS = {
    'lm_studio': { port: 1234, apiUrl: 'http://localhost:1234', apiFormat: 'openai' },
    'ollama': { port: 11434, apiUrl: 'http://localhost:11434', apiFormat: 'ollama' },
    'llama_cpp': { port: 8080, apiUrl: 'http://localhost:8080', apiFormat: 'openai' },
    'localai': { port: 8080, apiUrl: 'http://localhost:8080', apiFormat: 'openai' },
    'vllm': { port: 8000, apiUrl: 'http://localhost:8000', apiFormat: 'openai' },
    'custom': { port: 1234, apiUrl: 'http://localhost:1234', apiFormat: 'openai' }
};

// DOM elements
let serverTypeSelect;
let apiUrlInput;
let selectedModelInput;
let apiFormatSelect;
let requestTimeoutInput;
let testResultDiv;
let modelListDiv;
let statusMessage;

/**
 * Initialize options page
 */
async function init() {
    // Get DOM elements
    serverTypeSelect = document.getElementById('serverType');
    apiUrlInput = document.getElementById('apiUrl');
    selectedModelInput = document.getElementById('selectedModel');
    apiFormatSelect = document.getElementById('apiFormat');
    requestTimeoutInput = document.getElementById('requestTimeout');
    testResultDiv = document.getElementById('testResult');
    modelListDiv = document.getElementById('modelList');
    statusMessage = document.getElementById('statusMessage');
    
    // Load current settings
    await loadSettings();
    
    // Set up event listeners
    setupEventListeners();
}

/**
 * Load current settings
 */
async function loadSettings() {
    const settings = await getLlmSettings();
    
    serverTypeSelect.value = settings.serverType || 'lm_studio';
    apiUrlInput.value = settings.apiUrl || 'http://localhost:1234';
    selectedModelInput.value = settings.selectedModel || '';
    apiFormatSelect.value = settings.apiFormat || 'openai';
    requestTimeoutInput.value = settings.requestTimeout || 180;
}

/**
 * Setup event listeners
 */
function setupEventListeners() {
    // Server type change
    serverTypeSelect.addEventListener('change', handleServerTypeChange);
    
    // API format change
    apiFormatSelect.addEventListener('change', handleApiFormatChange);
    
    // Test connection
    document.getElementById('testConnection').addEventListener('click', handleTestConnection);
    
    // List models
    document.getElementById('listModels').addEventListener('click', handleListModels);
    
    // Save settings
    document.getElementById('saveBtn').addEventListener('click', handleSaveSettings);
    
    // Cancel
    document.getElementById('cancelBtn').addEventListener('click', () => window.close());
    
    // Reset to defaults
    document.getElementById('resetBtn').addEventListener('click', handleReset);
    
    // Open documentation
    document.getElementById('openDocsBtn').addEventListener('click', () => {
        browser.tabs.create({ url: '/src/docs/documentation.html' });
    });
}

/**
 * Handle server type change
 */
function handleServerTypeChange() {
    const serverType = serverTypeSelect.value;
    const defaults = SERVER_DEFAULTS[serverType];
    
    if (defaults) {
        apiUrlInput.value = defaults.apiUrl;
        apiFormatSelect.value = defaults.apiFormat;
    }
}

/**
 * Handle API format change
 */
function handleApiFormatChange() {
    // API format changed - might need to update endpoint
}

/**
 * Handle test connection
 */
async function handleTestConnection() {
    const testBtn = document.getElementById('testConnection');
    testBtn.disabled = true;
    
    showTestResult('Testing connection...', 'loading');
    
    try {
        // Save current values temporarily to test
        const tempSettings = {
            serverType: serverTypeSelect.value,
            apiUrl: apiUrlInput.value,
            selectedModel: selectedModelInput.value,
            apiFormat: apiFormatSelect.value,
            port: parseInt(apiUrlInput.value.split(':').pop()) || 1234,
            requestTimeout: Math.min(Math.max(parseInt(requestTimeoutInput.value) || 30, 5), 300)
        };
        
        await saveLlmSettings(tempSettings);
        
        const result = await testLlmConnection();
        
        if (result.success) {
            const modelCount = result.models?.length || 0;
            showTestResult(
                `✓ Connection successful! Found ${modelCount} model(s)${modelCount > 0 ? ': ' + result.models.join(', ') : ''}`,
                'success'
            );
        } else {
            showTestResult(
                `✗ Connection failed: ${result.error}`,
                'error'
            );
        }
    } catch (error) {
        showTestResult(
            `✗ Connection failed: ${error.message}`,
            'error'
        );
    } finally {
        testBtn.disabled = false;
    }
}

/**
 * Handle list models
 */
async function handleListModels() {
    const listBtn = document.getElementById('listModels');
    listBtn.disabled = true;
    modelListDiv.style.display = 'none';
    
    try {
        // Save current values temporarily
        const tempSettings = {
            serverType: serverTypeSelect.value,
            apiUrl: apiUrlInput.value,
            apiFormat: apiFormatSelect.value,
            port: parseInt(apiUrlInput.value.split(':').pop()) || 1234,
            requestTimeout: Math.min(Math.max(parseInt(requestTimeoutInput.value) || 30, 5), 300)
        };
        
        await saveLlmSettings(tempSettings);
        
        const models = await getAvailableModels(tempSettings);
        
        if (models.length > 0) {
            displayModels(models);
        } else {
            showTestResult('No models found. Make sure your LLM server has models loaded.', 'error');
        }
    } catch (error) {
        showTestResult(`Failed to fetch models: ${error.message}`, 'error');
    } finally {
        listBtn.disabled = false;
    }
}

/**
 * Display available models
 */
function displayModels(models) {
    modelListDiv.innerHTML = '';
    modelListDiv.style.display = 'block';
    
    const currentModel = selectedModelInput.value;
    
    models.forEach(model => {
        const modelItem = document.createElement('div');
        modelItem.className = 'model-item';
        if (model === currentModel) {
            modelItem.classList.add('selected');
        }
        
        const modelName = document.createElement('span');
        modelName.className = 'model-name';
        modelName.textContent = model;
        
        modelItem.appendChild(modelName);
        
        // Add recommended badge for preferred models
        const preferredModels = ['llama-3', 'llama3', 'mistral', 'qwen'];
        if (preferredModels.some(p => model.toLowerCase().includes(p))) {
            const badge = document.createElement('span');
            badge.className = 'model-badge';
            badge.textContent = 'Recommended';
            modelItem.appendChild(badge);
        }
        
        modelItem.addEventListener('click', () => {
            selectedModelInput.value = model;
            document.querySelectorAll('.model-item').forEach(item => {
                item.classList.remove('selected');
            });
            modelItem.classList.add('selected');
        });
        
        modelListDiv.appendChild(modelItem);
    });
}

/**
 * Handle save settings
 */
async function handleSaveSettings() {
    const saveBtn = document.getElementById('saveBtn');
    saveBtn.disabled = true;
    
    try {
const settings = {
            serverType: serverTypeSelect.value,
            apiUrl: apiUrlInput.value,
            selectedModel: selectedModelInput.value,
            apiFormat: apiFormatSelect.value,
            port: parseInt(apiUrlInput.value.split(':').pop()) || 1234,
            requestTimeout: Math.min(Math.max(parseInt(requestTimeoutInput.value) || 30, 5), 300),
            lastChecked: new Date().toISOString(),
            validated: false
        };
        
        const success = await saveLlmSettings(settings);
        
        if (success) {
            showStatusMessage('Settings saved successfully!', 'success');
            setTimeout(() => {
                hideStatusMessage();
            }, 3000);
        } else {
            showStatusMessage('Failed to save settings', 'error');
        }
    } catch (error) {
        showStatusMessage(`Error: ${error.message}`, 'error');
    } finally {
        saveBtn.disabled = false;
    }
}

/**
 * Handle reset to defaults
 */
async function handleReset() {
    if (confirm('Reset all settings to defaults?')) {
        serverTypeSelect.value = 'lm_studio';
        handleServerTypeChange();
        selectedModelInput.value = '';
        requestTimeoutInput.value = 180;
        showStatusMessage('Settings reset to defaults. Click Save to apply.', 'success');
    }
}

/**
 * Show test result
 */
function showTestResult(message, type) {
    testResultDiv.textContent = message;
    testResultDiv.className = `test-result ${type}`;
}

/**
 * Show status message
 */
function showStatusMessage(message, type) {
    statusMessage.textContent = message;
    statusMessage.className = `status-message ${type}`;
}

/**
 * Hide status message
 */
function hideStatusMessage() {
    statusMessage.className = 'status-message';
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', init);
