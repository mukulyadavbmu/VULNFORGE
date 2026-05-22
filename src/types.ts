export type AuthContext = 'guest' | 'userA' | 'userB' | 'admin';

export type NodeType = 'page' | 'api';

export interface AttackNode {
  id: string;
  url: string;
  method?: string;
  type: NodeType;
  authContext: AuthContext;
  params: string[];
  tags: string[];
  riskScore?: number;
  priorityScore?: number; // Adaptive prioritization score
  attackDepthLevel?: number; // 1 (low) to 5 (deep)
  fuzzBudget?: {
    mutations: number;
    replays: number;
    verifyDepth: 'shallow' | 'deep';
    maxRoleTransitions: number; // Max number of cross-role HTTP requests
    verificationRetries: number; // Max replay verification attempts
  };
}

export interface AttackEdge {
  id: string;
  fromNodeId: string;
  toNodeId: string;
  actionType: 'navigate' | 'form_submit' | 'api_call';
  authContext: AuthContext;
}

export type FindingClassification =
  | 'intelligence'
  | 'misconfiguration'
  | 'vulnerability'
  | 'confirmed_exploit';

/**
 * Reliability tier for findings — increases after successful replay verification.
 * signal → probable → confirmed → reproducible → stateful_confirmed
 */
export type ReliabilityTier =
  | 'signal'          // Raw detection — no verification
  | 'probable'        // Multi-signal detection but not verified
  | 'confirmed'       // Single successful replay
  | 'reproducible'    // ≥2/3 replays succeeded, stable signatures
  | 'stateful_confirmed'; // Verified with live state mutation observed

export type ReplayStatus = 'pending' | 'in_progress' | 'failed' | 'success';

export interface VerificationHistoryEntry {
  timestamp: number;
  result: 'success' | 'failure' | 'timeout';
  diffScore: number;
  successRate?: number;
  notes?: string;
}

export type FindingType =
  | 'sqli'
  | 'xss'
  | 'dom_xss'
  | 'bac'
  | 'idor'
  | 'auth_weakness'
  | 'sensitive_endpoint'
  | 'ssti'
  | 'csti'
  | 'rce'
  | 'oast'
  | 'config'
  | 'anomaly'
  | 'ssrf'
  | 'lfi'
  | 'cors'
  | 'info'
  | 'file_upload'
  | 'websocket'
  | 'csrf'
  | 'clickjacking'
  | 'race_condition'
  | 'cache_deception'
  | 'proto_pollution'
  | 'graphql_deep'
  | 'graphql_introspection'
  | 'graphql_dos'
  | 'graphql_auth_bypass'
  | 'auth_bypass'
  | 'jwt_weakness'
  | 'jwt_manipulation'
  | 'token_replay'
  | 'hidden_admin'
  | 'param_pollution'
  | 'api_abuse'
  | 'business_logic_abuse'
  | 'price_manipulation'
  | 'mass_assignment'
  | 'password_reset_flaw'
  | 'rate_limit_bypass'
  | 'http_smuggling';

/**
 * Classify a finding type into intelligence, misconfiguration, vulnerability, or confirmed_exploit.
 */
export function classifyFinding(type: FindingType, isExploitConfirmed?: boolean): FindingClassification {
  if (isExploitConfirmed) return 'confirmed_exploit';

  // Intelligence: recon-derived data (secrets, subdomains, fingerprints, info disclosure)
  const intelligenceTypes: FindingType[] = [
    'info', 'sensitive_endpoint', 'hidden_admin', 'config', 'anomaly',
  ];
  if (intelligenceTypes.includes(type)) return 'intelligence';

  // Misconfiguration: security misconfigurations
  const misconfigurationTypes: FindingType[] = [
    'cors', 'csrf', 'clickjacking',
  ];
  if (misconfigurationTypes.includes(type)) return 'misconfiguration';

  // Vulnerability: exploitable security flaws
  return 'vulnerability';
}

/**
 * Compute initial reliability tier from confidence score.
 * Used when first creating a finding before any replay verification.
 */
export function initialReliabilityTier(confidence: number): ReliabilityTier {
  if (confidence >= 80) return 'probable';
  return 'signal';
}

/**
 * Upgrade or downgrade a reliability tier based on replay verification outcome.
 */
export function computeReliabilityTier(
  currentTier: ReliabilityTier,
  replaySuccessRate: number,
  stateMutated: boolean,
  totalAttempts: number
): ReliabilityTier {
  if (replaySuccessRate === 0) {
    // Failed replay — downgrade
    return 'signal';
  }
  if (stateMutated && replaySuccessRate >= 0.66) {
    return 'stateful_confirmed';
  }
  if (replaySuccessRate >= 0.66 && totalAttempts >= 3) {
    return 'reproducible';
  }
  if (replaySuccessRate >= 0.5) {
    return 'confirmed';
  }
  return 'probable';
}

export interface ScanFinding {
  id: string;
  type: FindingType;
  classification: FindingClassification;
  url: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  evidence: string;
  aiExplanation?: string;
  metrics?: {
    diffScore?: number;
    timeDelta?: number;
    errorSignature?: string;
    confidence?: number;
    impact?: string;
    riskScore?: number;
  };
  // ENHANCED: Reporting improvements
  payload?: string; // Payload used to trigger the finding
  exploitReliability?: number; // 0-1: how reliably this can be exploited
  exploitExample?: string; // Example exploit request/code
  impactDescription?: string; // Business/security impact
  remediationSteps?: string[]; // Steps to fix the vulnerability
  cvssScore?: number; // CVSS score if known
  // PHASE 2C: Reliability Classification
  reliabilityTier?: ReliabilityTier;
  replayStatus?: ReplayStatus;
  verificationHistory?: VerificationHistoryEntry[];
}

export interface AIAttackAction {
  id: string;
  targetNodeId: string;
  actionType:
  | 'cross_role_access'
  | 'id_tamper'
  | 'repeat_as_guest'
  | 'xss_probe'
  | 'sqli_probe'
  | 'ssti_probe'
  | 'csti_probe'
  | 'rce_probe'
  | 'oast_probe'
  | 'config_probe'
  | 'anomaly_probe'
  | 'ssrf_probe'
  | 'path_traversal_probe'
  | 'cors_probe'
  | 'graphql_probe'
  | 'nosqli_probe'
  | 'file_upload_probe'
  | 'websocket_probe'
  | 'csrf_probe'
  | 'clickjacking_probe'
  | 'race_condition_probe'
  | 'cache_deception_probe'
  | 'proto_pollution_probe'
  | 'graphql_deep_probe'
  | 'auth_bypass_probe'
  | 'jwt_analysis_probe'
  | 'token_replay_probe'
  | 'hidden_admin_probe'
  | 'param_pollution_probe'
  | 'api_abuse_probe'
  | 'business_logic_probe'
  | 'cart_manipulation_probe'
  | 'coupon_abuse_probe'
  | 'checkout_bypass_probe';
  riskScore: number;
  explanation: string;
  expectedSignal?: string;
  result?: {
    status: number;
    responseSnippet?: string; // Short snippet for AI analysis
    diffScore?: number;
    errorSignature?: string;
    sanitizationInfo?: string; // e.g. "Reflected but encoded"
    success: boolean;
  };
}

/** Budget usage tracking for diagnostics — stored per-node in ScanSession */
export interface BudgetUsage {
  mutationsUsed: number;
  replaysUsed: number;
  roleTransitionsUsed: number;
  verificationRetriesUsed: number;
}

export interface ScanSession {
  id: string;
  targetUrl: string;
  status:
  | 'queued'
  | 'planning'
  | 'recon'
  | 'crawling'
  | 'attacking'
  | 'verifying'
  | 'paused'
  | 'failed'
  | 'stopped'
  | 'completed';
  createdAt: number;
  authHeaders: Record<AuthContext, Record<string, string>>;
  attackNodes: Record<string, AttackNode>;
  attackEdges: Record<string, AttackEdge>;
  actions: AIAttackAction[];
  findings: ScanFinding[];
  coverageMetrics?: {
    totalEndpoints: number;
    endpointsCovered: number;
    authBoundariesTested: number;
    rolesTested: number;
    totalPrivilegeTransitions: number;
    // Missing fields restored
    endpointsDiscovered: number;
    endpointsAttacked: number;
    authenticatedEndpointsTested: number;
    roleTestedEndpoints: number;
    parametersFuzzed: number;
    attackSuccessCount: number;
    attackFailureCount: number;
    replayAttempts: number;
    replaySuccesses: number;
    skippedAttacks: Record<string, number>;
    failedVerifications: Record<string, number>;
  };
  budgetUsage?: Record<string, BudgetUsage>;
  diagnosticsLogs?: any[]; // Allow string or object arrays
}

export type BrowserArtifactType = 'routes' | 'apis' | 'websockets' | 'storage' | 'dom_sinks' | 'correlation';

export interface RouteTransition {
  fromPath: string;
  toPath: string;
  type: 'pushState' | 'replaceState' | 'popstate' | 'link';
  timestamp: number;
}

export interface InterceptedAPI {
  url: string;
  method: string;
  requestHeaders: string[];
  requestBodySchema?: string;
  responseStatus: number;
  responseSchema?: string;
  authSensitive: boolean;
  mutationCapable: boolean;
}

export interface WebSocketSummary {
  url: string;
  protocols: string;
  messagesSent: number;
  messagesReceived: number;
  authTokensDetected: boolean;
  sampleFrames: any[];
}

export interface StorageSnapshot {
  origin: string;
  localStorageKeys: string[];
  sessionStorageKeys: string[];
  cookies: string[]; // only names, no values
  indexedDBDatabases: string[];
  hasHighEntropyTokens: boolean;
}

export interface DOMSink {
  url: string;
  sinkType: 'innerHTML' | 'eval' | 'document.write' | 'setTimeout' | 'postMessage';
  stackTrace?: string;
  timestamp: number;
}
