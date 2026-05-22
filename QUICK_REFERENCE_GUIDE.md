# VulnForge Quick Reference Guide — March 2026

## Overview

VulnForge is an advanced vulnerability scanner that behaves like a real attacker. This guide documents the 12-phase enhancement system for developers, security testers, and operators.

---

## Module Quick Reference

### 1. BrowserVerificationEngine
**Purpose**: Detect DOM-based vulnerabilities via headless browser  
**File**: `src/services/browser/BrowserVerificationEngine.ts`

```typescript
import { BrowserVerificationEngine } from './services/browser/BrowserVerificationEngine';

const engine = new BrowserVerificationEngine();
const findings = await engine.verifyEndpoints(attackNodes, session);
// Returns: BrowserFinding[] with DOM XSS detections
```

**Key Methods**:
- `verifyEndpoints()`: Main entry point, process up to 5 pages
- `verifyPayload()`: Single payload injection with monitoring
- `cleanup()`: Browser pool shutdown

**Confidence Tiers**:
- 1.0: alert() executed
- 0.95: payload in eval()
- 0.85: payload in innerHTML
- 0.70: payload in DOM but no execution trace

**Timeouts**:
- Per-page: 60 seconds
- Per-payload: 5 seconds
- Browser startup: 30 seconds

---

### 2. ParameterFuzzer
**Purpose**: Generate context-aware payload mutations  
**File**: `src/services/fuzzing/ParameterFuzzer.ts`

```typescript
import { ParameterFuzzer } from './services/fuzzing/ParameterFuzzer';

const fuzzer = new ParameterFuzzer();
const payloads = await fuzzer.generatePayloads(endpoint, param, basePayload);
// Returns: string[] of mutation variants
```

**Payload Contexts**:
- `'sql'`: SQL injection patterns (`' OR '1'='1`)
- `'json'`: JSON injection (`{$gt: ""}`)
- `'graphql'`: GraphQL patterns
- `'html'`: HTML context (`">, <script>`)
- `'unknown'`: Default patterns

**Limits**:
- Max 10 payloads per parameter
- Max 10 parameters per endpoint
- Max 10 variations per mutation strategy

**Strategies**:
1. json_nested (NoSQL queries)
2. array_injection
3. boolean_coercion
4. object_injection (prototype pollution)
5. null_injection
6. unicode_encoding
7. double_url_encoding

---

### 3. GraphQLAttackEngine
**Purpose**: Detect GraphQL endpoints and exploit them  
**File**: `src/services/intelligence/GraphQLAttackEngine.ts`

```typescript
import { GraphQLAttackEngine } from './services/intelligence/GraphQLAttackEngine';

const engine = new GraphQLAttackEngine();
const results = await engine.detectAndExploit(endpoints, session);
// Returns: GraphQLProbeResult[] with vulnerabilities
```

**Detected Vulnerabilities**:
- `graphql_introspection`: Schema publicly accessible (0.95 confidence)
- `graphql_dos`: Query complexity unlimited (0.80 confidence)
- `graphql_auth_bypass`: Admin access via aliases (0.75 confidence)
- `graphql_field_exposure`: Sensitive fields accessible (0.70 confidence)

**Probe Limits**:
- Max 5 GraphQL endpoints tested
- Per-query: 5 second timeout
- Per-endpoint: 10 second timeout

**Probes Executed**:
1. Introspection query
2. Deep nesting (10 levels)
3. Field duplication (20 copies)
4. Alias abuse

---

### 4. LoginDetector
**Purpose**: Auto-detect login endpoints and extract sessions  
**File**: `src/services/recon/LoginDetector.ts`

```typescript
import { LoginDetector } from './services/recon/LoginDetector';

const detector = new LoginDetector();
const result = await detector.detectAndLogin(crawlEndpoints, session);
// Populates: session.authHeaders with userA/userB auth contexts
```

**Default Credentials** (33 total):
- Admin: admin/admin, admin/password, admin/123456
- Test: test/test, test/password
- Juice Shop: admin@juice-sh.op/admin123, jim@juice-sh.op/ncc-1701

**Session Capture**:
- Cookies parsed from Set-Cookie headers
- JWT tokens extracted from Authorization headers
- Bearer tokens detected automatically

**Detection Success Indicators**:
- 2xx status code
- Missing error keywords (invalid, incorrect, failed)

---

### 5. BusinessLogicTester
**Purpose**: Detect business logic vulnerabilities  
**File**: `src/services/intelligence/BusinessLogicTester.ts`

```typescript
import { BusinessLogicTester } from './services/intelligence/BusinessLogicTester';

const tester = new BusinessLogicTester();
const findings = await tester.testEndpoints(attackNodes, session);
// Returns: BusinessLogicTest[] with exploitation evidence
```

**Tests Included**:
1. **Negative Quantity** (post negative values)
   - Confidence: 0.75
   - Severity: High

2. **Price Manipulation** (submit 0.01 price)
   - Confidence: 0.85
   - Severity: Critical

3. **Discount Abuse** (discount_percent: 999)
   - Confidence: 0.80
   - Severity: High

4. **Race Condition** (5 concurrent checkouts)
   - Confidence: 0.75
   - Severity: High

**Timeout**: 15 seconds per endpoint

---

### 6. ExploitVerifier
**Purpose**: Confirm exploitability with multi-attempt verification  
**File**: `src/services/intelligence/ExploitVerifier.ts`

```typescript
import { ExploitVerifier } from './services/intelligence/ExploitVerifier';

const verifier = new ExploitVerifier();
const result = await verifier.verifyExploit(finding, executor, session);
// Returns: VerifyResult with confidence and classification
```

**Confidence Rules**:
- 3/3 successes: 95% → `confirmed_exploit`
- 2/3 successes: 75% → `vulnerability`
- 1/3 successes: 45% → `intelligence`

**Stability Check**:
- All successful responses must have identical signature
- Tolerance: ±10% content length variance

**Auto-Classification**:
```typescript
if (successRate >= 1.0 || (successRate >= 0.66 && stable && reflected))
    classification = 'confirmed_exploit';
else if (reproducible && confidence >= 70)
    classification = 'vulnerability';
else
    classification = 'intelligence';
```

**Bonus Points**:
- +5 for payload reflection detected
- +5 for privilege escalation detected

**Timeout**: 20 seconds maximum (5 per attempt)

---

### 7. Enhanced Crawler
**Purpose**: Discover endpoints via form extraction and JS route discovery  
**File**: `src/crawler.ts`

```typescript
// Integrated into explorePage() function
// NEW features automatically applied:
```

**Form Extraction**:
- HTML form parsing with field enumeration
- CSRF token auto-detection
- Hidden field identification
- Method determination (GET/POST)

**JS Route Discovery**:
- Route pattern extraction from `<script>` tags
- Regex: `/[a-zA-Z0-9\-_./:?#&=~+%]+/g`
- Max 20 routes per page
- Automatic queue addition

**Limits**:
- Max 20 pages per session
- Skip list: socket.io, assets, fonts, media

---

### 8. Enhanced Attack Handlers
**Purpose**: Execute 21 different attack probes  
**File**: `src/attacks/handlers.ts`

```typescript
import { 
    jwt_manipulation_probe,
    rate_limit_bypass_probe,
    password_reset_probe,
    file_upload_polyglot_probe,
    http_smuggling_probe
} from './attacks/handlers';

// Each probe called with (endpoint, session)
```

**New Probes** (Phase 8):

1. **JWT Manipulation**
   - Tests "none" algorithm
   - Detects disabled verification
   - Severity: Critical

2. **Rate Limit Bypass**
   - 10 concurrent requests
   - Success threshold: ≥9/10 pass
   - Severity: Medium

3. **Password Reset Flaw**
   - Tests token validation
   - Payloads: weak token formats
   - Severity: Critical

4. **File Upload Polyglot**
   - Polyglot image+code payload
   - Extension evasion (.php.jpg, etc)
   - Severity: Critical

5. **HTTP Request Smuggling**
   - CL.TE technique (chunked + content-length conflict)
   - Severity: High

6. **Mass Assignment**
   - Parameter injection on PATCH/PUT
   - Role/privilege parameter testing
   - Severity: High

---

### 9. Multi-Signal Detection
**Purpose**: Improve accuracy via signal correlation  
**File**: `src/utils/scanUtils.ts`

```typescript
import { sqliMultiSignal, xssMultiSignal } from './utils/scanUtils';

const sqliResult = sqliMultiSignal(baseResponse, injectedResponse, timeDelta);
// Returns: { signals: string[], confidence: number }

const xssResult = xssMultiSignal(baseResponse, injectedResponse, payload, marker);
// Returns: { signals: string[], confidence: number }
```

**SQLi Signals** (requires ≥2):
1. Error signature (SQL keywords + brackets)
2. Boolean difference (>30% response variance)
3. Timing difference (>2.5s on SLEEP())
4. Structure change (schema/table pattern)

**XSS Signals** (requires ≥2):
1. Payload reflection (unencoded)
2. DOM sink (script, onerror, innerHTML)
3. Encoding context (HTML/JS/attribute)
4. Browser execution (alert, console, eval)

**Confidence Calculation**:
```
confidence = (signals.length / 4) * 100
```

---

## Classification System

### Finding Types
```typescript
enum FindingType {
  // Original types
  sql_injection = 'sql_injection',
  xss = 'xss',
  csrf = 'csrf',
  bac = 'broken_access_control',
  idor = 'insecure_direct_object_reference',
  // ... others

  // NEW Phase 1-9 types
  dom_xss = 'dom_xss',
  graphql_introspection = 'graphql_introspection',
  graphql_dos = 'graphql_dos',
  graphql_auth_bypass = 'graphql_auth_bypass',
  business_logic_abuse = 'business_logic_abuse',
  race_condition = 'race_condition',
  jwt_manipulation = 'jwt_manipulation',
  rate_limit_bypass = 'rate_limit_bypass',
  password_reset_flaw = 'password_reset_flaw',
  http_smuggling = 'http_smuggling',
  file_upload_rce = 'file_upload_rce',
  mass_assignment = 'mass_assignment',
}
```

### Classification Levels
```typescript
type Classification = 
  | 'confirmed_exploit'  // 3/3 success, stable, reproducible
  | 'vulnerability'      // 2/3+ success, ≥70% confidence
  | 'intelligence'       // 1/3 success, potential avenue
  | 'suspicious'         // Anomaly detected, needs investigation
```

---

## Scoring System

### ScoringWeights (9 dimensions)
```typescript
interface ScoringWeights {
  endpointSensitivity?: number;        // 0.25 weight
  parameterRichness?: number;          // 0.20 weight
  hypothesisConfidence?: number;       // 0.20 weight
  techniqueTechMatch?: number;         // 0.15 weight
  historicalExploitSuccess?: number;   // 0.10 weight
  randomness?: number;                 // 0.10 weight (0-0.1 range)
  authContext?: number;
  endpointSensitivityRefined?: number;
}
```

### Formula
```
score = (endpoint_sensitivity * 0.25) +
        (parameter_richness * 0.20) +
        (hypothesis_confidence * 0.20) +
        (tech_match * 0.15) +
        (historical_success * 0.10) +
        (randomness * 0.10)
```

---

## Usage Example — Full Scanner Run

```typescript
import { scanOrchestrator } from './scanOrchestrator';
import { logger } from './utils/logger';

async function runVulnForgeScan(targetUrl: string) {
  try {
    // Start scan
    const session = await scanOrchestrator(
      targetUrl,
      {
        depth: 3,
        timeout: 600000, // 10 minutes
        includeAuthenticated: true,
        generateReport: true,
      }
    );

    // Results available in session.findings[]
    logger.info(`Found ${session.findings.length} vulnerabilities`);
    
    // Filter by classification
    const confirmed = session.findings.filter(
      f => f.classification === 'confirmed_exploit'
    );
    logger.info(`Confirmed exploits: ${confirmed.length}`);
    
    // Generate report
    await generateReport(session, 'SCAN_REPORT.md');

  } catch (error) {
    logger.error(`Scan failed: ${error.message}`);
  }
}

runVulnForgeScan('https://juice-shop.herokuapp.com');
```

---

## Configuration Tuning

### Performance Tuning
```typescript
// In relevant service files:
const MAX_CONCURRENT_PAGES = 5;           // Browser parallelism
const MAX_FUZZ_ATTEMPTS_PER_ENDPOINT = 20; // Fuzzer iterations
const MAX_PARAMS_PER_ENDPOINT = 10;       // Parameter limit
const REQUEST_TIMEOUT_MS = 5000;          // HTTP timeout
const BROWSER_PAGE_TIMEOUT_MS = 60000;    // Browser timeout
```

### Accuracy Tuning
```typescript
// In scanUtils.ts:
const SIGNAL_REQUIREMENT = 2;             // Min signals needed
const TIMING_THRESHOLD_MS = 2500;         // SQLi timing detection
const RESPONSE_VARIANCE_THRESHOLD = 0.30; // Boolean SQLi threshold
const CONFIDENCE_THRESHOLD = 0.70;        // Finding creation threshold
```

---

## Troubleshooting

### Common Issues

**Issue**: "No browsers available"
```
Cause: BrowserPool exhausted, max 1 concurrent instance
Fix: Check for hanging browser processes, verify cleanup on error
```

**Issue**: "Timeout on endpoint"
```
Cause: Target endpoint slow or hanging
Fix: Increase REQUEST_TIMEOUT_MS, reduce concurrent operations
```

**Issue**: "False positive on XSS detection"
```
Cause: Insufficient signals collected
Fix: Verify multi-signal requirements (≥2 signals), check payload encoding
```

**Issue**: "GraphQL queries returning 403"
```
Cause: Auth required for GraphQL endpoint
Fix: Run with authenticated session (loginDetector should populate)
```

### Debug Mode
```bash
# Enable debug logging
export NODE_DEBUG=vulnforge:*
npm run scan

# Or in code:
logger.transports[0].level = 'debug';
```

---

## Performance Baseline

### Expected Metrics
```
Target: OWASP Juice Shop
Scan Duration: 5-15 minutes
Endpoints Discovered: 40-60
Vulnerabilities Found: 50-100
False Positives: 2-5%
Browser Sessions: 1 (reused)
HTTP Requests: 500-1000
Average Response Time: 200-500ms
```

### Resource Usage
```
Memory: 200-500MB
CPU: 30-50% average
Network: ~5-10MB transferred
Browser: 1 instance, ~100MB per context
```

---

## Integration with Existing Tools

### With OWASP ZAP
VulnForge findings can be converted to ZAP format:
```xml
<alertitem>
  <pluginid>{{finding.findingType}}</pluginid>
  <alert>{{finding.title}}</alert>
  <riskcode>{{finding.severity}}</riskcode>
  <confidence>{{finding.confidence * 100}}</confidence>
</alertitem>
```

### With SonarQube
Export findings via `findings.json`:
```bash
npm run scan -- --export json > findings.json
# Then import into SonarQube via API
```

---

## Best Practices

1. **Always verify findings before reporting**
   - Use `exploitVerifier` for confirmation
   - Check classification level (confirmed_exploit > vulnerability)

2. **Use authenticated sessions for sensitive endpoints**
   - Run loginDetector first
   - Pass session.authHeaders to handlers

3. **Respect target rate limits**
   - Reduce MAX_CONCURRENT_PAGES if getting 503s
   - Increase REQUEST_TIMEOUT_MS for slow targets

4. **Monitor browser memory**
   - Close browser via `engine.cleanup()` after use
   - Check for hanging browser processes

5. **Review multi-signal detections**
   - Trust findings with 4/4 signals (100% confidence)
   - Investigate 2/4 signal findings manually

---

## Support & Resources

- **Documentation**: See README.md in project root
- **Issues**: GitHub Issues tracker
- **Security**: Report to security@vulnforge.dev (DO NOT open public issue)

---

**Quick Reference Version**: 1.0  
**Last Updated**: March 6, 2026  
**Compatible with**: VulnForge v1.9+

