/**
 * Type definitions and state management for email phishing triage
 * Shared between Outlook and Thunderbird versions
 */

/**
 * Valid verdict values
 */
export const VERDICTS = ['legitimate', 'malicious', 'unknown'];

/**
 * Check if a value is a valid verdict
 * @param {unknown} value 
 * @returns {boolean}
 */
export function isValidVerdict(value) {
  return VERDICTS.includes(value);
}

/**
 * Validate LLM response structure
 * @param {unknown} obj 
 * @returns {boolean}
 */
export function isValidLlmResponse(obj) {
  if (!obj || typeof obj !== 'object') return false;
  
  const r = obj;
  
  return (
    isValidVerdict(r.verdict) &&
    typeof r.confidence === 'number' &&
    r.confidence >= 0 &&
    r.confidence <= 100 &&
    Array.isArray(r.reasons) &&
    r.reasons.every((x) => typeof x === 'string') &&
    Array.isArray(r.next_steps) &&
    r.next_steps.every((x) => typeof x === 'string')
  );
}

// Session cache for scan results
const scanCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

/**
 * Get cached scan result
 * @param {string} messageId 
 * @returns {object|null}
 */
export function getCachedScan(messageId) {
  const cached = scanCache.get(messageId);
  if (!cached) return null;
  
  const now = Date.now();
  if (now - cached.timestamp > CACHE_TTL) {
    scanCache.delete(messageId);
    return null;
  }
  
  return cached.result;
}

/**
 * Cache a scan result
 * @param {string} messageId 
 * @param {object} result 
 */
export function setCachedScan(messageId, result) {
  scanCache.set(messageId, { result, timestamp: Date.now() });
}

/**
 * Clear all cached scans
 */
export function clearScanCache() {
  scanCache.clear();
}
