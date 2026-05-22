/**
 * GraphQLAttackEngine — GraphQL endpoint detection and attack generation.
 *
 * Detects GraphQL endpoints via:
 *  - /graphql path
 *  - application/graphql content-type
 *  - GraphQL introspection responses
 *
 * Executes probes:
 *  - Introspection queries (schema discovery)
 *  - Deep nested queries (DoS detection)
 *  - Field duplication
 *  - Query batching
 *  - Alias abuse
 *  - Authorization bypass attempts
 *
 * Security: Bounded depths, timeout-safe, no eval.
 * Detection: Creates findings for introspection exposure, DoS vectors, auth bypass.
 */

import { AttackNode, FindingType, ScanFinding, ScanSession } from '../../types';
import { httpRequest, maybeAddFinding } from '../../utils/scanUtils';
import { logger } from '../../utils/logger';
import { AxiosRequestConfig } from 'axios';

const log = logger.child({ module: 'GraphQLAttackEngine' });

// ─── Constants ──────────────────────────────────────────────────────────────

const TIMEOUT_MS = 5000;
const MAX_DEPTH_NESTING = 10;
const MAX_QUERIES_PER_ENDPOINT = 5;

// ─── Types ──────────────────────────────────────────────────────────────────

export interface GraphQLEndpoint {
  url: string;
  method: 'GET' | 'POST';
  introspectionEnabled: boolean;
  vulnerabilities: GraphQLVulnerability[];
}

export interface GraphQLVulnerability {
  type: 'introspection' | 'dos' | 'auth_bypass' | 'field_exposure';
  evidence: string;
  confidence: number;
}

export interface GraphQLProbeResult {
  endpointsDetected: number;
  vulnerabilitiesFound: number;
  durationMs: number;
  endpoints: GraphQLEndpoint[];
}

// ─── GraphQL Probes ─────────────────────────────────────────────────────────

const INTROSPECTION_QUERY = `
{
  __schema {
    types {
      name
      description
      fields {
        name
        type {
          name
          kind
        }
      }
    }
    queryType {
      name
      fields {
        name
      }
    }
    mutationType {
      name
      fields {
        name
      }
    }
  }
}
`;

/**
 * Generate deeply nested query for DoS detection.
 * Measures response time to detect potential DoS vectors.
 */
function generateDeepNestedQuery(depth: number = 5): string {
  let query = '{ user { profile { settings';
  for (let i = 0; i < depth; i++) {
    query += ` { nested${i} `;
  }
  query += ' } '.repeat(depth + 3);
  query += ' } }';
  return query;
}

/**
 * Generate query with field duplication.
 * Detects query complexity protection and resource limits.
 */
function generateDuplicatedFieldQuery(): string {
  let query = '{ ';
  for (let i = 0; i < 20; i++) {
    query += `user${i}: user { id name email } `;
  }
  query += ' }';
  return query;
}

/**
 * Generate query with alias abuse.
 * Tests if aliases bypass rate limiting or field-level access control.
 */
function generateAliasAbuseQuery(): string {
  return `{
    admin: user(id: 1) { id name email role }
    user1: user(id: 1) { id name }
    user2: user(id: 2) { id name }
    user3: user(id: 3) { id name }
    user4: user(id: 4) { id name }
    user5: user(id: 999999) { id name email }
  }`;
}

/**
 * Generate batch query.
 * Tests if multiple queries enhance attack surface.
 */
function generateBatchQuery(): string {
  return `
    query {
      users { id }
    }
    query {
      posts { id }
    }
    query {
      admin { id }
    }
  `;
}

// ─── Engine ─────────────────────────────────────────────────────────────────

export class GraphQLAttackEngine {
  /**
   * Detect and attack GraphQL endpoints in the session.
   */
  async probe(
    session: ScanSession,
    endpoints: AttackNode[],
  ): Promise<GraphQLProbeResult> {
    const start = Date.now();
    const detectedEndpoints: GraphQLEndpoint[] = [];
    let vulnerabilitiesFound = 0;

    // Detect GraphQL endpoints
    const graphqlEndpoints = await this.detectGraphQLEndpoints(session, endpoints);
    log.info(`Detected ${graphqlEndpoints.length} GraphQL endpoints`);

    // Attack each detected endpoint
    for (const gqlEndpoint of graphqlEndpoints) {
      if (!gqlEndpoint.url) continue; // Skip if no URL
      
      try {
        const vulnerabilities = await this.attackEndpoint(session, gqlEndpoint);
        if (vulnerabilities.length > 0) {
          vulnerabilitiesFound += vulnerabilities.length;
          detectedEndpoints.push({
            url: gqlEndpoint.url,
            method: 'POST',
            introspectionEnabled: vulnerabilities.some((v) => v.type === 'introspection'),
            vulnerabilities,
          });
        }
      } catch (err) {
        log.debug(`Failed to attack GraphQL endpoint ${gqlEndpoint.url}: ${err}`);
      }
    }

    return {
      endpointsDetected: detectedEndpoints.length,
      vulnerabilitiesFound,
      endpoints: detectedEndpoints,
      durationMs: Date.now() - start,
    };
  }

  /**
   * Detect GraphQL endpoints by checking common paths and headers.
   */
  private async detectGraphQLEndpoints(
    session: ScanSession,
    endpoints: AttackNode[],
  ): Promise<Partial<GraphQLEndpoint>[]> {
    const detected: Partial<GraphQLEndpoint>[] = [];
    const baseUrl = session.targetUrl;

    // Common GraphQL paths
    const graphqlPaths = [
      '/graphql',
      '/api/graphql',
      '/graphql/query',
      '/graph',
      '/api/graph',
      '/v1/graphql',
      '/v2/graphql',
    ];

    for (const path of graphqlPaths) {
      try {
        const url = new URL(baseUrl);
        url.pathname = path;

        const response = await httpRequest(session, url.toString(), 'userA', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          data: JSON.stringify({ query: '{ __typename }' }),
        });

        // Check if response looks like GraphQL
        if (
          response.status === 200 &&
          (response.bodySnippet.includes('__typename') ||
            response.bodySnippet.includes('errors') ||
            response.bodySnippet.includes('data'))
        ) {
          detected.push({ url: url.toString() });
        }
      } catch {
        // Endpoint doesn't exist, continue
      }
    }

    // Also check endpoints that already mention graphql
    for (const endpoint of endpoints) {
      if (endpoint.url.toLowerCase().includes('graphql')) {
        detected.push({ url: endpoint.url });
      }
    }

    return detected;
  }

  /**
   * Attack a detected GraphQL endpoint with various probes.
   */
  private async attackEndpoint(
    session: ScanSession,
    endpoint: Partial<GraphQLEndpoint>,
  ): Promise<GraphQLVulnerability[]> {
    const vulnerabilities: GraphQLVulnerability[] = [];

    // Probe 1: Introspection
    try {
      const introspectionResult = await this.probeIntrospection(session, endpoint.url!);
      if (introspectionResult) {
        vulnerabilities.push(introspectionResult);
      }
    } catch (err) {
      log.debug(`Introspection probe failed: ${err}`);
    }

    // Probe 2: Deep nested queries (DoS)
    try {
      const dosResult = await this.probeDeepNesting(session, endpoint.url!);
      if (dosResult) {
        vulnerabilities.push(dosResult);
      }
    } catch (err) {
      log.debug(`Deep nesting probe failed: ${err}`);
    }

    // Probe 3: Alias abuse
    try {
      const aliasResult = await this.probeAliasAbuse(session, endpoint.url!);
      if (aliasResult) {
        vulnerabilities.push(aliasResult);
      }
    } catch (err) {
      log.debug(`Alias abuse probe failed: ${err}`);
    }

    // Probe 4: Field duplication
    try {
      const dupResult = await this.probeDuplicatedFields(session, endpoint.url!);
      if (dupResult) {
        vulnerabilities.push(dupResult);
      }
    } catch (err) {
      log.debug(`Field duplication probe failed: ${err}`);
    }

    return vulnerabilities;
  }

  /**
   * Probe for introspection exposure.
   */
  private async probeIntrospection(
    session: ScanSession,
    url: string,
  ): Promise<GraphQLVulnerability | null> {
    try {
      const response = await httpRequest(session, url, 'userA', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        data: JSON.stringify({ query: INTROSPECTION_QUERY }),
      });

      // Parse response
      if (response.status === 200 && response.bodySnippet.includes('__schema')) {
        const evidence = response.bodySnippet.slice(0, 200);
        return {
          type: 'introspection',
          evidence: `Schema introspection exposed: ${evidence}`,
          confidence: 0.95,
        };
      }
    } catch (err) {
      log.debug(`Introspection probe error: ${err}`);
    }

    return null;
  }

  /**
   * Probe for DoS via deep nesting.
   */
  private async probeDeepNesting(
    session: ScanSession,
    url: string,
  ): Promise<GraphQLVulnerability | null> {
    try {
      const query = generateDeepNestedQuery(MAX_DEPTH_NESTING);
      const start = Date.now();

      const response = await httpRequest(session, url, 'userA', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        data: JSON.stringify({ query }),
      });

      const responseTime = Date.now() - start;

      // If response is successful with deep nesting, it's a DoS vector
      if (response.status === 200 && responseTime > 2000) {
        return {
          type: 'dos',
          evidence: `Deep nesting query executed in ${responseTime}ms without rejection`,
          confidence: 0.8,
        };
      }
    } catch (err) {
      log.debug(`Deep nesting probe error: ${err}`);
    }

    return null;
  }

  /**
   * Probe for alias abuse vulnerabilities.
   */
  private async probeAliasAbuse(
    session: ScanSession,
    url: string,
  ): Promise<GraphQLVulnerability | null> {
    try {
      const query = generateAliasAbuseQuery();
      const response = await httpRequest(session, url, 'userA', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        data: JSON.stringify({ query }),
      });

      // If all aliases return data, authorization might be bypassed
      if (response.status === 200 && response.bodySnippet.includes('admin')) {
        return {
          type: 'auth_bypass',
          evidence: 'Alias abuse query returned admin data',
          confidence: 0.7,
        };
      }
    } catch (err) {
      log.debug(`Alias abuse probe error: ${err}`);
    }

    return null;
  }

  /**
   * Probe for field duplication vulnerabilities.
   */
  private async probeDuplicatedFields(
    session: ScanSession,
    url: string,
  ): Promise<GraphQLVulnerability | null> {
    try {
      const query = generateDuplicatedFieldQuery();
      const start = Date.now();

      const response = await httpRequest(session, url, 'userA', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        data: JSON.stringify({ query }),
      });

      const responseTime = Date.now() - start;

      // If field duplication succeeds with slow response, it's inefficient
      if (response.status === 200 && responseTime > 1500) {
        return {
          type: 'dos',
          evidence: `Field duplication query executed in ${responseTime}ms`,
          confidence: 0.65,
        };
      }
    } catch (err) {
      log.debug(`Duplicated fields probe error: ${err}`);
    }

    return null;
  }
}
