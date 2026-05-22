/**
 * Enhanced Response Analysis Module
 * Provides sophisticated detection beyond simple string matching
 * Addresses the #3 detection gap: 50% of vulnerabilities missed due to weak response analysis
 */

import { logger } from '../../utils/logger';
import * as crypto from 'crypto';

export interface ResponseSignature {
  statusCode: number;
  contentLength: number;
  bodyHash: string;
  headers: Record<string, string>;
  timeMs: number;
}

export interface SQLiSignals {
  errorSignature: boolean;
  booleanDifference: boolean;
  timingAnomaly: boolean;
  structureChange: boolean;
  rowCountChange: boolean;
  confidence: number;
  signals: string[];
}

export interface XSSSignals {
  payloadReflected: boolean;
  unescapedReflection: boolean;
  domSink: boolean;
  javascriptContext: boolean;
  htmlContext: boolean;
  attributeContext: boolean;
  confidence: number;
  signals: string[];
}

export class ResponseAnalyzer {
  
  /**
   * Create response signature for comparison
   */
  createSignature(response: { status: number; data: any; headers: any }, timeMs: number): ResponseSignature {
    const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
    return {
      statusCode: response.status,
      contentLength: body.length,
      bodyHash: crypto.createHash('md5').update(body).digest('hex'),
      headers: response.headers || {},
      timeMs,
    };
  }

  /**
   * Enhanced SQLi detection with multiple signals
   */
  analyzeSQLi(
    baseResponse: string,
    injectedResponse: string,
    baseStatus: number,
    injectedStatus: number,
    baseTime: number,
    injectedTime: number,
    payload: string
  ): SQLiSignals {
    const signals: string[] = [];
    let confidence = 0;

    // Signal 1: SQL error signatures
    const sqlErrorPatterns = [
      /SQL syntax.*?error/i,
      /mysql_fetch/i,
      /pg_query/i,
      /sqlite.{0,20}error/i,
      /Oracle error/i,
      /ODBC.*?Driver/i,
      /SQLServer/i,
      /PostgreSQL.*?ERROR/i,
      /Warning.*?mysql/i,
      /valid MySQL result/i,
      /MySqlClient\./i,
      /Unclosed quotation mark/i,
      /quoted string not properly terminated/i,
      /SQLSTATE\[\w+\]/i,
      /syntax error.*?near/i,
    ];

    const hasErrorSignature = sqlErrorPatterns.some(pattern => pattern.test(injectedResponse));
    if (hasErrorSignature) {
      signals.push('sql_error_signature');
      confidence += 0.4;
    }

    // Signal 2: Boolean-based response difference
    const responseDiff = this.calculateStructuralDifference(baseResponse, injectedResponse);
    const hasBooleanDifference = responseDiff > 0.25 && baseStatus === injectedStatus;
    if (hasBooleanDifference) {
      signals.push('boolean_difference');
      confidence += 0.3;
    }

    // Signal 3: Timing anomaly (for SLEEP/WAITFOR queries)
    const timeDelta = injectedTime - baseTime;
    const hasTimingAnomaly = timeDelta > 2500 && /sleep|waitfor|benchmark|pg_sleep/i.test(payload);
    if (hasTimingAnomaly) {
      signals.push('timing_anomaly');
      confidence += 0.35;
    }

    // Signal 4: Row count change (JSON array length difference)
    const hasRowCountChange = this.detectRowCountChange(baseResponse, injectedResponse);
    if (hasRowCountChange) {
      signals.push('row_count_change');
      confidence += 0.25;
    }

    // Signal 5: Structure change (JSON structure completely different)
    const hasStructureChange = this.detectStructureChange(baseResponse, injectedResponse);
    if (hasStructureChange && baseStatus === 200 && injectedStatus === 200) {
      signals.push('structure_change');
      confidence += 0.2;
    }

    // Signal 6: Server error on injection
    if (injectedStatus >= 500 && baseStatus < 500) {
      signals.push('server_error');
      confidence += 0.3;
    }

    return {
      errorSignature: hasErrorSignature,
      booleanDifference: hasBooleanDifference,
      timingAnomaly: hasTimingAnomaly,
      structureChange: hasStructureChange,
      rowCountChange: hasRowCountChange,
      confidence: Math.min(confidence, 1.0),
      signals,
    };
  }

  /**
   * Enhanced XSS detection with multiple signals
   */
  analyzeXSS(
    response: string,
    payload: string,
    browserExecuted?: boolean
  ): XSSSignals {
    const signals: string[] = [];
    let confidence = 0;

    // Signal 1: Payload reflected in response
    const payloadReflected = response.includes(payload);
    if (payloadReflected) {
      signals.push('payload_reflected');
      confidence += 0.2;
    }

    // Signal 2: Unescaped reflection (dangerous characters present)
    const dangerousChars = ['<', '>', '"', "'", '`'];
    const unescapedReflection = payloadReflected && dangerousChars.some(char => 
      payload.includes(char) && response.includes(char)
    );
    if (unescapedReflection) {
      signals.push('unescaped_reflection');
      confidence += 0.3;
    }

    // Signal 3: DOM sink detection
    const domSinkPatterns = [
      /<script[^>]*>[\s\S]*?<\/script>/i,
      /onerror\s*=\s*["'][^"']*["']/i,
      /onload\s*=\s*["'][^"']*["']/i,
      /onclick\s*=\s*["'][^"']*["']/i,
      /javascript:/i,
      /eval\s*\(/i,
      /innerHTML/i,
      /document\.write/i,
    ];

    const hasDomSink = payloadReflected && domSinkPatterns.some(pattern => pattern.test(response));
    if (hasDomSink) {
      signals.push('dom_sink');
      confidence += 0.35;
    }

    // Signal 4: JavaScript context detection
    const jsContextPatterns = [
      /<script[^>]*>[\s\S]*?\{payload\}[\s\S]*?<\/script>/i,
      /var\s+\w+\s*=\s*["']?\{payload\}["']?/i,
      /\(\s*["']?\{payload\}["']?\s*\)/i,
    ];

    const javascriptContext = jsContextPatterns.some(pattern => 
      pattern.test(response.replace('{payload}', payload))
    );
    if (javascriptContext) {
      signals.push('javascript_context');
      confidence += 0.25;
    }

    // Signal 5: HTML context detection
    const htmlContextPatterns = [
      new RegExp(`<[^>]*${this.escapeRegex(payload)}[^>]*>`, 'i'),
      new RegExp(`>${this.escapeRegex(payload)}<`, 'i'),
    ];

    const htmlContext = htmlContextPatterns.some(pattern => pattern.test(response));
    if (htmlContext) {
      signals.push('html_context');
      confidence += 0.2;
    }

    // Signal 6: Attribute context detection
    const attrContextPatterns = [
      new RegExp(`\\w+\\s*=\\s*["'][^"']*${this.escapeRegex(payload)}[^"']*["']`, 'i'),
      new RegExp(`href\\s*=\\s*["'][^"']*${this.escapeRegex(payload)}[^"']*["']`, 'i'),
      new RegExp(`src\\s*=\\s*["'][^"']*${this.escapeRegex(payload)}[^"']*["']`, 'i'),
    ];

    const attributeContext = attrContextPatterns.some(pattern => pattern.test(response));
    if (attributeContext) {
      signals.push('attribute_context');
      confidence += 0.2;
    }

    // Signal 7: Browser execution confirmation (from BrowserVerificationEngine)
    if (browserExecuted) {
      signals.push('browser_execution');
      confidence += 0.5; // Very high confidence if browser executed
    }

    return {
      payloadReflected,
      unescapedReflection,
      domSink: hasDomSink,
      javascriptContext,
      htmlContext,
      attributeContext,
      confidence: Math.min(confidence, 1.0),
      signals,
    };
  }

  /**
   * Calculate structural difference between two responses
   * Returns value between 0 (identical) and 1 (completely different)
   */
  private calculateStructuralDifference(str1: string, str2: string): number {
    if (str1 === str2) return 0;
    
    // If responses are JSON, compare structure
    try {
      const obj1 = JSON.parse(str1);
      const obj2 = JSON.parse(str2);
      
      const keys1 = this.getAllKeys(obj1);
      const keys2 = this.getAllKeys(obj2);
      
      const intersection = keys1.filter(k => keys2.includes(k));
      const union = [...new Set([...keys1, ...keys2])];
      
      return 1 - (intersection.length / union.length);
      
    } catch {
      // Not JSON, use Levenshtein-like distance
      const maxLen = Math.max(str1.length, str2.length);
      if (maxLen === 0) return 0;
      
      const lengthDiff = Math.abs(str1.length - str2.length);
      return lengthDiff / maxLen;
    }
  }

  /**
   * Detect row count change in JSON responses
   */
  private detectRowCountChange(str1: string, str2: string): boolean {
    try {
      const obj1 = JSON.parse(str1);
      const obj2 = JSON.parse(str2);
      
      const array1 = this.findArrays(obj1);
      const array2 = this.findArrays(obj2);
      
      if (array1.length > 0 && array2.length > 0) {
        // Check if any array length changed significantly
        for (let i = 0; i < Math.min(array1.length, array2.length); i++) {
          const diff = Math.abs(array1[i] - array2[i]);
          if (diff > 0) return true;
        }
      }
      
      return false;
    } catch {
      return false;
    }
  }

  /**
   * Detect JSON structure change
   */
  private detectStructureChange(str1: string, str2: string): boolean {
    try {
      const obj1 = JSON.parse(str1);
      const obj2 = JSON.parse(str2);
      
      // Compare top-level structure
      const type1 = Array.isArray(obj1) ? 'array' : typeof obj1;
      const type2 = Array.isArray(obj2) ? 'array' : typeof obj2;
      
      if (type1 !== type2) return true;
      
      if (typeof obj1 === 'object' && typeof obj2 === 'object') {
        const keys1 = Object.keys(obj1).sort();
        const keys2 = Object.keys(obj2).sort();
        
        return JSON.stringify(keys1) !== JSON.stringify(keys2);
      }
      
      return false;
    } catch {
      return false;
    }
  }

  /**
   * Get all keys from nested object
   */
  private getAllKeys(obj: any, prefix = ''): string[] {
    if (typeof obj !== 'object' || obj === null) return [];
    
    let keys: string[] = [];
    for (const key of Object.keys(obj)) {
      const fullKey = prefix ? `${prefix}.${key}` : key;
      keys.push(fullKey);
      
      if (typeof obj[key] === 'object' && obj[key] !== null) {
        keys = keys.concat(this.getAllKeys(obj[key], fullKey));
      }
    }
    
    return keys;
  }

  /**
   * Find all array lengths in object
   */
  private findArrays(obj: any): number[] {
    if (!obj || typeof obj !== 'object') return [];
    
    let lengths: number[] = [];
    
    if (Array.isArray(obj)) {
      lengths.push(obj.length);
    }
    
    for (const value of Object.values(obj)) {
      if (typeof value === 'object' && value !== null) {
        lengths = lengths.concat(this.findArrays(value));
      }
    }
    
    return lengths;
  }

  /**
   * Escape special regex characters
   */
  private escapeRegex(str: string): string {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  /**
   * Compare two signatures for stability
   */
  compareSignatures(sig1: ResponseSignature, sig2: ResponseSignature): {
    stable: boolean;
    differences: string[];
  } {
    const differences: string[] = [];
    
    if (sig1.statusCode !== sig2.statusCode) {
      differences.push('status_code');
    }
    
    const lengthDiff = Math.abs(sig1.contentLength - sig2.contentLength);
    const lengthTolerance = Math.max(sig1.contentLength, sig2.contentLength) * 0.1;
    if (lengthDiff > lengthTolerance) {
      differences.push('content_length');
    }
    
    if (sig1.bodyHash !== sig2.bodyHash) {
      differences.push('body_hash');
    }
    
    const timeDiff = Math.abs(sig1.timeMs - sig2.timeMs);
    if (timeDiff > 1000) {
      differences.push('response_time');
    }
    
    return {
      stable: differences.length === 0,
      differences,
    };
  }
}

// Global response analyzer instance
export const responseAnalyzer = new ResponseAnalyzer();
