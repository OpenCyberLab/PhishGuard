/**
 * Email parsing utilities: HTML->text, header extraction, attachment processing
 * Shared between Outlook and Thunderbird versions
 */

const MAX_BODY_LENGTH = 100 * 1024; // 100 KB

/**
 * Convert HTML to plain text with basic sanitization
 * @param {string} html 
 * @returns {string}
 */
export function htmlToText(html) {
  if (!html) return '';
  
  // Remove scripts and styles
  let text = html.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
  text = text.replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '');
  
  // Replace common HTML entities
  text = text.replace(/&nbsp;/g, ' ');
  text = text.replace(/&amp;/g, '&');
  text = text.replace(/&lt;/g, '<');
  text = text.replace(/&gt;/g, '>');
  text = text.replace(/&quot;/g, '"');
  text = text.replace(/&#39;/g, "'");
  
  // Replace <br> and block elements with newlines
  text = text.replace(/<br\s*\/?>/gi, '\n');
  text = text.replace(/<\/(div|p|h[1-6]|li|tr)>/gi, '\n');
  
  // Remove all remaining HTML tags
  text = text.replace(/<[^>]+>/g, '');
  
  // Normalize whitespace
  text = text.replace(/\r\n/g, '\n');
  text = text.replace(/\n\n+/g, '\n\n');
  text = text.trim();
  
  return text;
}

/**
 * Redact PII (emails, phone numbers) from text
 * @param {string} text 
 * @returns {string}
 */
export function redactPii(text) {
  // Redact email addresses
  let redacted = text.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, '[EMAIL_REDACTED]');
  
  // Redact phone numbers (various formats)
  redacted = redacted.replace(/\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g, '[PHONE_REDACTED]');
  redacted = redacted.replace(/\(\d{3}\)\s*\d{3}[-.]?\d{4}/g, '[PHONE_REDACTED]');
  
  return redacted;
}

/**
 * Truncate body text to max length
 * @param {string} text 
 * @param {number} maxLength 
 * @returns {string}
 */
export function truncateBody(text, maxLength = MAX_BODY_LENGTH) {
  if (text.length <= maxLength) return text;
  return text.substring(0, maxLength) + '\n\n[... body truncated for analysis ...]';
}

/**
 * Parse SPF result from Authentication-Results header
 * @param {string} authResults 
 * @returns {object}
 */
function parseSPF(authResults) {
  const result = { status: 'none', details: null };
  
  // Match patterns like: spf=pass (google.com: domain of sender@example.com designates 1.2.3.4 as permitted sender)
  const spfMatch = authResults.match(/spf=(\w+)(?:\s*\(([^)]+)\))?/i);
  if (spfMatch) {
    result.status = spfMatch[1].toLowerCase();
    result.details = spfMatch[2] || null;
  }
  
  // Also check Received-SPF header format
  return result;
}

/**
 * Parse DKIM result from Authentication-Results header
 * @param {string} authResults 
 * @returns {object}
 */
function parseDKIM(authResults) {
  const result = { status: 'none', domain: null, details: null };
  
  // Match patterns like: dkim=pass header.d=example.com header.s=selector
  const dkimMatch = authResults.match(/dkim=(\w+)(?:[^;]*header\.d=([^\s;]+))?/i);
  if (dkimMatch) {
    result.status = dkimMatch[1].toLowerCase();
    result.domain = dkimMatch[2] || null;
  }
  
  return result;
}

/**
 * Parse DMARC result from Authentication-Results header
 * @param {string} authResults 
 * @returns {object}
 */
function parseDMARC(authResults) {
  const result = { status: 'none', policy: null, details: null };
  
  // Match patterns like: dmarc=pass (p=reject dis=none)
  const dmarcMatch = authResults.match(/dmarc=(\w+)(?:\s*\(([^)]+)\))?/i);
  if (dmarcMatch) {
    result.status = dmarcMatch[1].toLowerCase();
    result.details = dmarcMatch[2] || null;
    
    // Extract policy if present
    const policyMatch = result.details?.match(/p=(\w+)/i);
    if (policyMatch) {
      result.policy = policyMatch[1].toLowerCase();
    }
  }
  
  return result;
}

/**
 * Extract comprehensive email authentication data from headers
 * @param {object} headers 
 * @returns {object}
 */
export function extractAuthenticationResults(headers) {
  if (!headers) return { spf: { status: 'unknown' }, dkim: { status: 'unknown' }, dmarc: { status: 'unknown' } };
  
  const auth = {
    spf: { status: 'none' },
    dkim: { status: 'none' },
    dmarc: { status: 'none' },
    raw: {}
  };
  
  // Get Authentication-Results header (may be multiple)
  const authResults = headers['authentication-results'] || '';
  
  if (authResults) {
    auth.spf = parseSPF(authResults);
    auth.dkim = parseDKIM(authResults);
    auth.dmarc = parseDMARC(authResults);
    auth.raw.authenticationResults = authResults;
  }
  
  // Also check Received-SPF header (some servers use this)
  const receivedSpf = headers['received-spf'] || '';
  if (receivedSpf && auth.spf.status === 'none') {
    const spfMatch = receivedSpf.match(/^(\w+)/i);
    if (spfMatch) {
      auth.spf.status = spfMatch[1].toLowerCase();
      auth.spf.details = receivedSpf;
    }
    auth.raw.receivedSpf = receivedSpf;
  }
  
  // Check for DKIM-Signature header (presence indicates signing attempt)
  const dkimSignature = headers['dkim-signature'] || '';
  if (dkimSignature) {
    auth.raw.dkimSignature = dkimSignature.substring(0, 200); // Truncate for brevity
    
    // Extract signing domain
    const domainMatch = dkimSignature.match(/d=([^;\s]+)/i);
    if (domainMatch && !auth.dkim.domain) {
      auth.dkim.domain = domainMatch[1];
    }
  }
  
  // Check ARC headers (for forwarded mail)
  const arcResults = headers['arc-authentication-results'] || '';
  if (arcResults) {
    auth.raw.arcResults = arcResults;
    auth.hasARC = true;
  }
  
  return auth;
}

/**
 * Extract email metadata from headers
 * @param {object} headers 
 * @returns {object}
 */
export function extractMetadata(headers) {
  if (!headers) return {};
  
  const metadata = {};
  
  // Get comprehensive authentication results
  const auth = extractAuthenticationResults(headers);
  metadata.authentication = auth;
  
  // Legacy compatibility
  metadata.spfStatus = auth.spf.status;
  metadata.dkimStatus = auth.dkim.status;
  metadata.dmarcStatus = auth.dmarc.status;
  
  // Extract sender domain for comparison
  const from = headers['from'] || '';
  metadata.senderDomain = extractDomain(from);
  
  // Extract Reply-To for mismatch detection
  const replyTo = headers['reply-to'] || '';
  metadata.replyToDomain = extractDomain(replyTo);
  
  // Check for domain mismatch (common phishing indicator)
  if (metadata.senderDomain && metadata.replyToDomain) {
    metadata.replyToMismatch = metadata.senderDomain.toLowerCase() !== metadata.replyToDomain.toLowerCase();
  }
  
  // Extract Return-Path for envelope sender comparison
  const returnPath = headers['return-path'] || '';
  metadata.returnPathDomain = extractDomain(returnPath);
  if (metadata.senderDomain && metadata.returnPathDomain) {
    metadata.returnPathMismatch = metadata.senderDomain.toLowerCase() !== metadata.returnPathDomain.toLowerCase();
  }
  
  // Count received hops (many hops can indicate forwarding or suspicious routing)
  let receivedCount = 0;
  for (const [key] of Object.entries(headers)) {
    if (key.toLowerCase() === 'received') {
      receivedCount++;
    }
  }
  metadata.receivedHops = receivedCount;
  
  // Check for suspicious headers
  metadata.hasXMailer = !!headers['x-mailer'];
  metadata.xMailer = headers['x-mailer'] || null;
  
  // Check for list headers (indicates mailing list, usually legitimate)
  metadata.isMailingList = !!(headers['list-unsubscribe'] || headers['list-id']);
  
  return metadata;
}

/**
 * Calculate authentication risk score
 * NOTE: Only explicit FAILURES add to risk score. Missing authentication (none/unknown)
 * is treated as neutral since many legitimate senders don't configure DKIM/DMARC.
 * @param {object} auth - Authentication results from extractAuthenticationResults
 * @returns {object} - Risk assessment
 */
export function calculateAuthRisk(auth) {
  let riskScore = 0;
  const issues = [];
  
  // SPF checks - only failures are concerning
  if (auth.spf.status === 'fail') {
    riskScore += 40;
    issues.push('SPF authentication failed - sender IP not authorized');
  } else if (auth.spf.status === 'softfail') {
    riskScore += 20;
    issues.push('SPF soft fail - sender IP may not be authorized');
  }
  // Note: 'none' and 'unknown' are neutral - no risk added
  
  // DKIM checks - only failures are concerning
  if (auth.dkim.status === 'fail') {
    riskScore += 35;
    issues.push('DKIM signature verification failed - message may be tampered');
  }
  // Note: 'none' and 'unknown' are neutral - many legitimate emails are unsigned
  
  // DMARC checks - only failures are concerning
  if (auth.dmarc.status === 'fail') {
    riskScore += 45;
    issues.push('DMARC policy check failed - high spoofing risk');
  }
  // Note: 'none' and 'unknown' are neutral - most domains don't have DMARC
  
  // Determine overall authentication status
  let overallStatus = 'neutral';
  if (auth.spf.status === 'pass' && auth.dkim.status === 'pass' && auth.dmarc.status === 'pass') {
    overallStatus = 'pass';
  } else if (auth.spf.status === 'fail' || auth.dkim.status === 'fail' || auth.dmarc.status === 'fail') {
    overallStatus = 'fail';
  } else if (auth.spf.status === 'pass' || auth.dkim.status === 'pass') {
    overallStatus = 'partial';
  }
  
  return {
    score: Math.min(riskScore, 100),
    status: overallStatus,
    issues,
    summary: riskScore === 0 ? 'No authentication failures detected' :
             riskScore < 30 ? 'Minor authentication concern' :
             riskScore < 60 ? 'Authentication issue detected' :
             'Significant authentication failures'
  };
}

/**
 * Extract sender domain from email address
 * @param {string} email 
 * @returns {string|undefined}
 */
export function extractDomain(email) {
  if (!email) return undefined;
  const match = email.match(/@([^>]+)>?$/);
  return match ? match[1].trim() : undefined;
}

/**
 * Flatten Thunderbird headers (arrays) to single values
 * @param {object} headers - Headers object with array values
 * @returns {object} - Headers object with string values
 */
export function flattenHeaders(headers) {
  if (!headers) return {};
  
  const flat = {};
  for (const [key, values] of Object.entries(headers)) {
    if (Array.isArray(values)) {
      flat[key.toLowerCase()] = values[0] || '';
    } else {
      flat[key.toLowerCase()] = values || '';
    }
  }
  return flat;
}

/**
 * Extract body text from fullMessage parts recursively
 * @param {object} part - Message part from getFull()
 * @returns {string} - Extracted body text
 */
function extractBodyFromParts(part) {
  if (!part) return '';
  
  let result = '';
  
  // Check if this part has body content
  if (part.body) {
    if (part.contentType === 'text/plain') {
      return part.body;
    } else if (part.contentType === 'text/html') {
      return htmlToText(part.body);
    }
  }
  
  // Recursively check parts
  if (part.parts && Array.isArray(part.parts)) {
    // Prefer plain text over HTML
    const plainPart = part.parts.find(p => p.contentType === 'text/plain');
    if (plainPart && plainPart.body) {
      return plainPart.body;
    }
    
    const htmlPart = part.parts.find(p => p.contentType === 'text/html');
    if (htmlPart && htmlPart.body) {
      return htmlToText(htmlPart.body);
    }
    
    // Check nested parts
    for (const subPart of part.parts) {
      const extracted = extractBodyFromParts(subPart);
      if (extracted) return extracted;
    }
  }
  
  return result;
}

/**
 * Parse message from Thunderbird messenger API data
 * @param {object} data - Data from background script containing messageInfo, fullMessage, textParts, attachments
 * @returns {object} - Parsed message payload with authentication data
 */
export function parseThunderbirdMessage(data) {
  const { messageInfo, fullMessage, textParts, attachments } = data;
  
  // Get body text - try multiple approaches
  let bodyText = '';
  
  // Approach 1: Use textParts if available (newer API)
  if (textParts && textParts.length > 0) {
    const plainTextPart = textParts.find(p => p.contentType === 'text/plain');
    const htmlPart = textParts.find(p => p.contentType === 'text/html');
    
    if (plainTextPart && plainTextPart.content) {
      bodyText = plainTextPart.content;
    } else if (htmlPart && htmlPart.content) {
      bodyText = htmlToText(htmlPart.content);
    }
  }
  
  // Approach 2: Extract from fullMessage parts (fallback)
  if (!bodyText && fullMessage) {
    bodyText = extractBodyFromParts(fullMessage);
  }
  
  // Approach 3: If still no body, use a placeholder
  if (!bodyText) {
    bodyText = '[Email body could not be retrieved]';
  }
  
  // Flatten headers
  const headers = flattenHeaders(fullMessage?.headers);
  
  // Extract comprehensive metadata including authentication
  const metadata = extractMetadata(headers);
  
  // Calculate authentication risk
  const authRisk = calculateAuthRisk(metadata.authentication);
  
  // Process attachments
  const attachmentList = (attachments || []).map(att => ({
    id: att.partName || att.name,
    name: att.name || 'unnamed',
    size: att.size || 0,
    contentType: att.contentType,
  }));
  
  // Build payload with authentication data
  const payload = {
    internetMessageId: headers['message-id'],
    subject: messageInfo?.subject || '(No Subject)',
    from: messageInfo?.author || undefined,
    to: messageInfo?.recipients || [],
    cc: messageInfo?.ccList || [],
    bodyText: truncateBody(redactPii(bodyText)),
    headers: headers,
    attachments: attachmentList,
    // Authentication data
    authentication: {
      spf: metadata.authentication.spf,
      dkim: metadata.authentication.dkim,
      dmarc: metadata.authentication.dmarc,
      risk: authRisk
    },
    // Additional security indicators
    securityIndicators: {
      replyToMismatch: metadata.replyToMismatch || false,
      returnPathMismatch: metadata.returnPathMismatch || false,
      isMailingList: metadata.isMailingList || false,
      receivedHops: metadata.receivedHops || 0,
      senderDomain: metadata.senderDomain,
      replyToDomain: metadata.replyToDomain,
      returnPathDomain: metadata.returnPathDomain
    }
  };
  
  return payload;
}
