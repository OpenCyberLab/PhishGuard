/**
 * Type definitions and state management for email phishing triage
 * Shared between Outlook and Thunderbird versions
 */

/**
 * Valid verdict values
 * - legitimate: Email appears safe
 * - suspicious: Email has some concerning elements but not definitively malicious
 * - malicious: Email shows clear signs of phishing/malicious intent
 * - unknown: Unable to determine (error state)
 */
export const VERDICTS = ['legitimate', 'suspicious', 'malicious', 'unknown'];

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
const CACHE_TTL = 10 * 60 * 1000; // 10 minutes (increased from 5)
const MAX_CACHE_SIZE = 50; // Maximum number of cached results

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
  // Enforce cache size limit - remove oldest entries if needed
  if (scanCache.size >= MAX_CACHE_SIZE) {
    // Find and remove the oldest entry
    let oldestKey = null;
    let oldestTime = Infinity;
    
    for (const [key, value] of scanCache.entries()) {
      if (value.timestamp < oldestTime) {
        oldestTime = value.timestamp;
        oldestKey = key;
      }
    }
    
    if (oldestKey) {
      scanCache.delete(oldestKey);
    }
  }
  
  scanCache.set(messageId, { result, timestamp: Date.now() });
}

/**
 * Clear all cached scans
 */
export function clearScanCache() {
  scanCache.clear();
}

/**
 * Get cache statistics (for debugging)
 * @returns {object}
 */
export function getCacheStats() {
  return {
    size: scanCache.size,
    maxSize: MAX_CACHE_SIZE,
    ttlMinutes: CACHE_TTL / 60000
  };
}
