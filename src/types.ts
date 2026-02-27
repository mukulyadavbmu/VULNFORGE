export type AuthContext = 'guest' | 'userA' | 'userB';

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
}

export interface AttackEdge {
  id: string;
  fromNodeId: string;
  toNodeId: string;
  actionType: 'navigate' | 'form_submit' | 'api_call';
  authContext: AuthContext;
}

export interface ScanFinding {
  id: string;
  type:
  | 'sqli'
  | 'xss'
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
  | 'graphql_deep';
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
  | 'graphql_deep_probe';
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

export interface ScanSession {
  id: string;
  targetUrl: string;
  status: 'running' | 'completed' | 'failed';
  createdAt: number;
  attackNodes: Record<string, AttackNode>;
  attackEdges: Record<string, AttackEdge>;
  findings: ScanFinding[];
  actions: AIAttackAction[];
  authHeaders: Record<AuthContext, Record<string, string>>;
}
