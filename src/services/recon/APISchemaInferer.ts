/**
 * APISchemaInferer — Infer API response schemas by probing endpoints.
 *
 * Analyzes JSON responses to detect field types and structures.
 * Uses schema to generate type-aware targeted payloads.
 *
 * No eval(). Bounded recursion (max depth 5). Timeout-safe.
 */
import { ScanSession, AttackNode } from '../../types';
import { httpRequest } from '../../utils/scanUtils';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'APISchemaInferer' });

// ─── Constants ──────────────────────────────────────────────────────────────

const MAX_ENDPOINTS_TO_PROBE = 30;
const MAX_SCHEMA_DEPTH = 5;
const MAX_ARRAY_SAMPLE = 3;

// ─── Types ──────────────────────────────────────────────────────────────────

export type FieldType = 'string' | 'number' | 'boolean' | 'object' | 'array' | 'null';

export interface FieldSchema {
    name: string;
    type: FieldType;
    children?: FieldSchema[];
    isId?: boolean;
    isSensitive?: boolean;
    sampleValue?: string;
}

export interface InferredSchema {
    endpointUrl: string;
    method: string;
    statusCode: number;
    contentType: string;
    responseFields: FieldSchema[];
    isArray: boolean;
    totalFields: number;
}

export interface SchemaInferenceResult {
    schemas: InferredSchema[];
    endpointsProbed: number;
    endpointsWithSchema: number;
    durationMs: number;
}

// ─── Sensitive Field Detection ──────────────────────────────────────────────

const ID_FIELD_PATTERNS = [
    /^id$/i, /^_id$/i, /^uuid$/i, /Id$/i, /_id$/i,
    /^pk$/i, /^key$/i, /^uid$/i,
];

const SENSITIVE_FIELD_PATTERNS = [
    /^email$/i, /^password$/i, /^secret$/i, /^token$/i,
    /^ssn$/i, /^credit/i, /^card/i, /^phone$/i,
    /^address$/i, /^dob$/i, /^birth/i, /^salary/i,
    /^api[_-]?key$/i, /^private/i, /^auth/i,
];

// ─── Payload Generation by Type ─────────────────────────────────────────────

const TYPE_PAYLOADS: Record<FieldType, string[]> = {
    string: ["'", "' OR '1'='1", '<script>alert(1)</script>', '{{7*7}}', '../../../etc/passwd'],
    number: ['-1', '0', '99999999', '1.1e308', 'NaN', "' OR 1=1--"],
    boolean: ['null', '""', '0', '[]', "' OR '1'='1"],
    object: ['[]', '""', 'null', '{"__proto__":{"admin":true}}'],
    array: ['{}', '""', 'null', '[{"__proto__":{"admin":true}}]'],
    null: ["''", '0', '[]', '{}', 'undefined'],
};

// ─── Engine ─────────────────────────────────────────────────────────────────

export class APISchemaInferer {

    /**
     * Probe API endpoints and infer JSON response schemas.
     */
    async inferSchemas(session: ScanSession, endpoints: AttackNode[]): Promise<SchemaInferenceResult> {
        const start = Date.now();
        const schemas: InferredSchema[] = [];
        let endpointsProbed = 0;

        // Only probe API-type endpoints
        const apiEndpoints = endpoints
            .filter(ep => ep.type === 'api' || ep.url.includes('/api/'))
            .slice(0, MAX_ENDPOINTS_TO_PROBE);

        for (const endpoint of apiEndpoints) {
            endpointsProbed++;

            try {
                const res = await httpRequest(session, endpoint.url, 'userA');

                // Only analyze JSON responses
                if (res.status >= 200 && res.status < 400) {
                    const schema = this.analyzeResponse(
                        res.bodySnippet,
                        endpoint.url,
                        endpoint.method ?? 'GET',
                        res.status,
                    );
                    if (schema && schema.totalFields > 0) {
                        schemas.push(schema);
                    }
                }
            } catch {
                // Skip failed probes
            }
        }

        const durationMs = Date.now() - start;
        log.info('Schema inference complete', {
            scanId: session.id,
            endpointsProbed,
            schemasInferred: schemas.length,
            durationMs,
        });

        return {
            schemas,
            endpointsProbed,
            endpointsWithSchema: schemas.length,
            durationMs,
        };
    }

    /**
     * Analyze a response body and produce a field schema.
     */
    analyzeResponse(
        body: string,
        endpointUrl: string,
        method: string,
        statusCode: number,
    ): InferredSchema | null {
        try {
            const parsed: unknown = JSON.parse(body);
            let fields: FieldSchema[];
            let isArray = false;

            if (Array.isArray(parsed)) {
                isArray = true;
                // Sample first element
                const sample = parsed[0];
                if (sample && typeof sample === 'object' && sample !== null) {
                    fields = this.buildObjectSchema(sample as Record<string, unknown>, 0);
                } else {
                    fields = [];
                }
            } else if (typeof parsed === 'object' && parsed !== null) {
                fields = this.buildObjectSchema(parsed as Record<string, unknown>, 0);
            } else {
                return null; // Not a JSON object/array
            }

            const totalFields = this.countFields(fields);

            return {
                endpointUrl,
                method,
                statusCode,
                contentType: 'application/json',
                responseFields: fields,
                isArray,
                totalFields,
            };
        } catch {
            return null; // Not valid JSON
        }
    }

    /**
     * Generate type-aware payloads based on inferred schema.
     */
    generateTargetedPayloads(schema: InferredSchema): Array<{ field: string; payloads: string[] }> {
        const result: Array<{ field: string; payloads: string[] }> = [];

        for (const field of schema.responseFields) {
            const payloads = TYPE_PAYLOADS[field.type] ?? TYPE_PAYLOADS.string;

            // ID fields get extra IDOR payloads
            if (field.isId) {
                const idPayloads = ['0', '1', '-1', '99999', "' OR 1=1--"];
                result.push({ field: field.name, payloads: [...idPayloads, ...payloads] });
            } else if (field.isSensitive) {
                // Sensitive fields get injection payloads
                result.push({ field: field.name, payloads: [...TYPE_PAYLOADS.string, ...payloads] });
            } else {
                result.push({ field: field.name, payloads });
            }
        }

        return result;
    }

    // ─── Private Helpers ────────────────────────────────────────────────

    private buildObjectSchema(obj: Record<string, unknown>, depth: number): FieldSchema[] {
        if (depth >= MAX_SCHEMA_DEPTH) return [];
        const fields: FieldSchema[] = [];

        for (const [key, value] of Object.entries(obj)) {
            const field = this.buildFieldSchema(key, value, depth);
            fields.push(field);
        }

        return fields;
    }

    private buildFieldSchema(name: string, value: unknown, depth: number): FieldSchema {
        const field: FieldSchema = {
            name,
            type: this.detectType(value),
            isId: ID_FIELD_PATTERNS.some(p => p.test(name)),
            isSensitive: SENSITIVE_FIELD_PATTERNS.some(p => p.test(name)),
        };

        // Store sample value (truncated)
        if (value !== null && value !== undefined) {
            const str = String(value);
            field.sampleValue = str.length > 50 ? str.slice(0, 47) + '...' : str;
        }

        // Recurse into objects
        if (field.type === 'object' && typeof value === 'object' && value !== null && !Array.isArray(value)) {
            field.children = this.buildObjectSchema(value as Record<string, unknown>, depth + 1);
        }

        // Recurse into arrays (sample first items)
        if (field.type === 'array' && Array.isArray(value)) {
            const sample = value.slice(0, MAX_ARRAY_SAMPLE);
            if (sample.length > 0 && typeof sample[0] === 'object' && sample[0] !== null) {
                field.children = this.buildObjectSchema(sample[0] as Record<string, unknown>, depth + 1);
            }
        }

        return field;
    }

    private detectType(value: unknown): FieldType {
        if (value === null || value === undefined) return 'null';
        if (typeof value === 'string') return 'string';
        if (typeof value === 'number') return 'number';
        if (typeof value === 'boolean') return 'boolean';
        if (Array.isArray(value)) return 'array';
        if (typeof value === 'object') return 'object';
        return 'string'; // fallback
    }

    private countFields(fields: FieldSchema[]): number {
        let count = fields.length;
        for (const field of fields) {
            if (field.children) {
                count += this.countFields(field.children);
            }
        }
        return count;
    }
}
