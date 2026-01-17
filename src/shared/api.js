/**
 * Local LLM API client (Multi-server support)
 * Supports LM Studio, Ollama, llama.cpp, and other OpenAI-compatible servers
 */

import { isValidLlmResponse } from './state.js';
import { getLlmSettings } from './config-manager.js';

const REQUEST_TIMEOUT = 30000; // 30 seconds

/**
 * List of popular email service provider domains that should never be recommended for blocking.
 * Phishing emails often spoof or originate from these legitimate services,
 * but blocking these domains would be counterproductive.
 */
const POPULAR_EMAIL_PROVIDER_DOMAINS = [
  // Major email providers
  'gmail.com',
  'googlemail.com',
  'outlook.com',
  'outlook.co',
  'hotmail.com',
  'hotmail.co.uk',
  'live.com',
  'msn.com',
  'yahoo.com',
  'yahoo.co.uk',
  'yahoo.co.in',
  'ymail.com',
  'aol.com',
  'icloud.com',
  'me.com',
  'mac.com',
  'protonmail.com',
  'proton.me',
  'zoho.com',
  'zohomail.com',
  'mail.com',
  'gmx.com',
  'gmx.net',
  'fastmail.com',
  'tutanota.com',
  'tuta.io',
  'yandex.com',
  'yandex.ru',
  'mail.ru',
  // Business/Enterprise providers
  'google.com',
  'microsoft.com',
  'apple.com',
  'amazon.com',
  'aws.amazon.com',
  // Regional providers
  'qq.com',
  '163.com',
  '126.com',
  'sina.com',
  'naver.com',
  'daum.net',
  'rediffmail.com',
  // ISP email services
  'att.net',
  'verizon.net',
  'comcast.net',
  'sbcglobal.net',
  'cox.net',
  'charter.net',
  'earthlink.net',
  'btinternet.com',
  'sky.com',
  'virginmedia.com',
  't-online.de',
  'web.de',
  'orange.fr',
  'free.fr',
  'laposte.net',
];

/**
 * Create the system prompt for the LLM
 * @returns {string}
 */
function createSystemPrompt() {
  return `You are an email security classifier specialized in phishing detection.

IMPORTANT: You will receive email data including EMAIL AUTHENTICATION RESULTS (SPF, DKIM, DMARC).
These are critical security indicators:

- SPF (Sender Policy Framework): Validates sender IP is authorized
  - pass = legitimate sender server
  - fail/softfail = sender IP not authorized (HIGH RISK)
  - none = no SPF record (moderate concern)

- DKIM (DomainKeys Identified Mail): Cryptographic signature verification  
  - pass = email not tampered, signature valid
  - fail = signature invalid, possible tampering (HIGH RISK)
  - none = not signed

- DMARC (Domain-based Message Authentication): Policy enforcement
  - pass = sender domain authenticated
  - fail = authentication failed, violates domain policy (VERY HIGH RISK)
  - none = no policy defined

RISK INTERPRETATION:
- All pass: Low risk (but still check content)
- SPF fail + DKIM fail: Very high spoofing risk
- DMARC fail: Strong indicator of domain spoofing
- Reply-To mismatch with From: Common phishing tactic
- Return-Path mismatch: Envelope sender differs from display sender

Analyze the email and respond with ONLY a JSON object (no markdown, no explanation):
{
  "verdict": "legitimate" or "malicious",
  "confidence": integer 0-100,
  "reasons": ["reason1", "reason2", ...] (max 5, include authentication findings),
  "next_steps": ["action1", "action2", ...] (max 4 actionable recommendations)
}

Weight authentication failures heavily - a DMARC fail should significantly increase malicious likelihood.`;
}

/**
 * Prepare message payload for LLM analysis
 * @param {object} message 
 * @returns {string}
 */
function prepareMessageForAnalysis(message) {
  // Build authentication summary for LLM
  const authSummary = message.authentication ? {
    spf: {
      status: message.authentication.spf?.status || 'unknown',
      details: message.authentication.spf?.details || null
    },
    dkim: {
      status: message.authentication.dkim?.status || 'unknown',
      domain: message.authentication.dkim?.domain || null
    },
    dmarc: {
      status: message.authentication.dmarc?.status || 'unknown',
      policy: message.authentication.dmarc?.policy || null
    },
    risk_assessment: message.authentication.risk ? {
      score: message.authentication.risk.score,
      status: message.authentication.risk.status,
      issues: message.authentication.risk.issues
    } : null
  } : null;
  
  // Build security indicators summary
  const securityIndicators = message.securityIndicators ? {
    reply_to_mismatch: message.securityIndicators.replyToMismatch,
    return_path_mismatch: message.securityIndicators.returnPathMismatch,
    is_mailing_list: message.securityIndicators.isMailingList,
    received_hops: message.securityIndicators.receivedHops,
    sender_domain: message.securityIndicators.senderDomain,
    reply_to_domain: message.securityIndicators.replyToDomain,
    return_path_domain: message.securityIndicators.returnPathDomain
  } : null;
  
  const summary = {
    subject: message.subject,
    from: message.from || 'unknown',
    to: message.to?.slice(0, 3) || [],
    body_preview: message.bodyText.substring(0, 4000), // Reduced to make room for auth data
    attachment_count: message.attachments.length,
    attachments: message.attachments.slice(0, 5).map((a) => ({
      name: a.name,
      type: a.contentType,
      size_kb: Math.round(a.size / 1024),
    })),
    // Email authentication results (critical for phishing detection)
    email_authentication: authSummary,
    // Additional security indicators
    security_indicators: securityIndicators,
    // Raw authentication headers for additional context
    raw_auth_headers: message.headers ? {
      authentication_results: message.headers['authentication-results']?.substring(0, 500),
      received_spf: message.headers['received-spf']?.substring(0, 300),
    } : null
  };
  
  return JSON.stringify(summary, null, 2);
}

/**
 * Scan email with LLM (OpenAI-compatible API)
 * @param {object} message - The parsed email message
 * @param {object} settings - LLM settings
 * @returns {Promise<object>} - LLM response
 */
async function scanWithOpenAI(message, settings) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);
  
  try {
    const apiUrl = `${settings.apiUrl}/v1/chat/completions`;
    
    // Get available models if no model is selected
    let modelToUse = settings.selectedModel;
    if (!modelToUse || modelToUse === 'local-model') {
      const models = await getAvailableModels(settings);
      modelToUse = models.length > 0 ? models[0] : 'local-model';
    }
    
    console.log('PhishGuard: Using OpenAI-compatible API:', apiUrl);
    
    const requestBody = {
      model: modelToUse,
      messages: [
        { role: 'system', content: createSystemPrompt() },
        { role: 'user', content: prepareMessageForAnalysis(message) },
      ],
      temperature: 0.0,
      max_tokens: 1000,
    };
    
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestBody),
      signal: controller.signal,
    });
    
    clearTimeout(timeoutId);
    
    if (!response.ok) {
      const errorText = await response.text().catch(() => 'Unknown error');
      console.error('PhishGuard: API error:', response.status, response.statusText, errorText);
      throw {
        message: `API error ${response.status}: ${response.statusText}`,
        type: 'api',
        details: errorText,
      };
    }
    
    const data = await response.json();
    
    // Extract content from OpenAI-compatible response
    const content = data.choices?.[0]?.message?.content;
    if (!content) {
      console.error('PhishGuard: No content in API response:', data);
      throw {
        message: 'No content in API response',
        type: 'parse',
        details: JSON.stringify(data),
      };
    }
    
    return parseAndValidateLlmResponse(content);
    
  } catch (error) {
    clearTimeout(timeoutId);
    throw error;
  }
}

/**
 * Scan email with Ollama API
 * @param {object} message - The parsed email message
 * @param {object} settings - LLM settings
 * @returns {Promise<object>} - LLM response
 */
async function scanWithOllama(message, settings) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);
  
  try {
    const apiUrl = `${settings.apiUrl}/api/generate`;
    
    // Ollama uses a different request format
    const systemPrompt = createSystemPrompt();
    const userContent = prepareMessageForAnalysis(message);
    
    const requestBody = {
      model: settings.selectedModel,
      prompt: `${systemPrompt}\n\nUser: ${userContent}\n\nAssistant:`,
      stream: false,
      format: 'json', // Request JSON output
      options: {
        temperature: 0.0,
        num_predict: 1000
      }
    };
    
    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestBody),
      signal: controller.signal,
    });
    
    clearTimeout(timeoutId);
    
    if (!response.ok) {
      const errorText = await response.text().catch(() => 'Unknown error');
      console.error('PhishGuard: Ollama API error:', response.status, response.statusText, errorText);
      throw {
        message: `Ollama API error ${response.status}: ${response.statusText}`,
        type: 'api',
        details: errorText,
      };
    }
    
    const data = await response.json();
    
    // Ollama returns response in 'response' field
    const content = data.response;
    if (!content) {
      console.error('PhishGuard: No response in Ollama API response:', data);
      throw {
        message: 'No response in Ollama API response',
        type: 'parse',
        details: JSON.stringify(data),
      };
    }
    
    return parseAndValidateLlmResponse(content);
    
  } catch (error) {
    clearTimeout(timeoutId);
    throw error;
  }
}

/**
 * Filter out inappropriate recommendations from next_steps.
 * Specifically removes "Block domain" suggestions for popular email service providers
 * since blocking these domains would be counterproductive.
 * @param {string[]} nextSteps - Array of recommendation strings
 * @returns {string[]} - Filtered recommendations
 */
function filterInappropriateRecommendations(nextSteps) {
  if (!Array.isArray(nextSteps)) {
    return nextSteps;
  }
  
  return nextSteps.filter(step => {
    const stepLower = step.toLowerCase();
    
    // Check if this is a "block domain" type recommendation
    const isBlockDomainRecommendation = 
      stepLower.includes('block domain') ||
      stepLower.includes('block the domain') ||
      stepLower.includes('block sender domain') ||
      stepLower.includes('blacklist domain') ||
      stepLower.includes('blacklist the domain') ||
      stepLower.includes('add domain to blocklist') ||
      stepLower.includes('add to blocklist');
    
    if (!isBlockDomainRecommendation) {
      return true; // Keep non-block recommendations
    }
    
    // Check if this recommendation mentions a popular email provider domain
    for (const domain of POPULAR_EMAIL_PROVIDER_DOMAINS) {
      if (stepLower.includes(domain.toLowerCase())) {
        return false; // Filter out this recommendation
      }
    }
    
    return true; // Keep block recommendations for other domains
  });
}

/**
 * Parse and validate LLM response
 * @param {string} content - Raw LLM response
 * @returns {object} - Validated response
 */
function parseAndValidateLlmResponse(content) {
  // Parse the LLM's JSON response
  let llmResponse;
  try {
    // Try to extract JSON from markdown code blocks if present
    const jsonMatch = content.match(/```(?:json)?\s*(\{[\s\S]*?\})\s*```/);
    const jsonStr = jsonMatch ? jsonMatch[1] : content;
    llmResponse = JSON.parse(jsonStr);
  } catch (e) {
    throw {
      message: 'Failed to parse LLM response as JSON',
      type: 'parse',
      details: content,
    };
  }
  
  // Validate response structure
  if (!isValidLlmResponse(llmResponse)) {
    throw {
      message: 'LLM response does not match expected schema',
      type: 'validation',
      details: JSON.stringify(llmResponse, null, 2),
    };
  }
  
  // Filter out inappropriate recommendations (e.g., blocking popular email providers)
  if (llmResponse.next_steps) {
    llmResponse.next_steps = filterInappropriateRecommendations(llmResponse.next_steps);
  }
  
  return llmResponse;
}

/**
 * Call the local LLM API (main entry point)
 * Routes to appropriate API based on settings
 * @param {object} message - The parsed email message
 * @returns {Promise<object>} - LLM response with verdict, confidence, reasons, next_steps
 */
export async function scanWithLlm(message) {
  try {
    // Load settings
    const settings = await getLlmSettings();
    
    // Route to appropriate API
    let result;
    if (settings.apiFormat === 'ollama') {
      result = await scanWithOllama(message, settings);
    } else {
      // Default to OpenAI-compatible (LM Studio, llama.cpp, etc.)
      result = await scanWithOpenAI(message, settings);
    }
    
    return result;
    
  } catch (error) {
    // Handle different error types
    if (error && typeof error === 'object' && 'type' in error) {
      throw error;
    }
    
    if (error.name === 'AbortError') {
      throw {
        message: 'Request timed out after 30 seconds',
        type: 'timeout',
      };
    }
    
    if (error instanceof TypeError && error.message.includes('fetch')) {
      const settings = await getLlmSettings();
      throw {
        message: 'Cannot connect to LLM server',
        type: 'network',
        details: `Make sure your LLM server is running at ${settings.apiUrl}. Error: ${error.message}`,
      };
    }
    
    throw {
      message: error instanceof Error ? error.message : 'Unknown error',
      type: 'network',
      details: String(error),
    };
  }
}

/**
 * Get available models from LLM server
 * @param {object} settings - LLM settings
 * @returns {Promise<string[]>}
 */
export async function getAvailableModels(settings = null) {
  try {
    // Load settings if not provided
    if (!settings) {
      settings = await getLlmSettings();
    }
    
    let modelsUrl;
    if (settings.apiFormat === 'ollama') {
      modelsUrl = `${settings.apiUrl}/api/tags`;
    } else {
      modelsUrl = `${settings.apiUrl}/v1/models`;
    }
    
    const response = await fetch(modelsUrl, {
      method: 'GET',
      signal: AbortSignal.timeout(5000),
    });
    
    if (!response.ok) {
      throw new Error(`Failed to fetch models: ${response.status}`);
    }
    
    const data = await response.json();
    
    // Parse based on API format
    if (settings.apiFormat === 'ollama') {
      // Ollama format: {"models": [{"name": "..."}]}
      return data.models?.map((model) => model.name) || [];
    } else {
      // OpenAI format: {"data": [{"id": "..."}]}
      return data.data?.map((model) => model.id) || [];
    }
  } catch (error) {
    return [];
  }
}

/**
 * Test connection to local LLM API
 * @returns {Promise<{success: boolean, error?: string, models?: string[]}>}
 */
export async function testLlmConnection() {
  try {
    // Load settings
    const settings = await getLlmSettings();
    
    let testUrl;
    if (settings.apiFormat === 'ollama') {
      testUrl = `${settings.apiUrl}/api/version`;
    } else {
      testUrl = `${settings.apiUrl}/v1/models`;
    }
    
    const response = await fetch(testUrl, {
      method: 'GET',
      signal: AbortSignal.timeout(5000),
    });
    
    if (!response.ok) {
      const errorText = await response.text().catch(() => 'Unknown error');
      return { success: false, error: `HTTP ${response.status}: ${errorText}` };
    }
    
    const models = await getAvailableModels(settings);
    return { success: true, models };
  } catch (error) {
    return { 
      success: false, 
      error: error instanceof Error ? error.message : String(error) 
    };
  }
}
