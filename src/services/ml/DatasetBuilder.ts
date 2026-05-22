/**
 * DatasetBuilder — Export scan data as JSONL datasets for ML training.
 *
 * Exports per-scan or global datasets with sanitized data.
 * Removes cookies, tokens, passwords, API keys from output.
 * Storage: datasets/ directory, named scan-<scanId>.jsonl.
 */
import { PrismaClient } from '@prisma/client';
import * as fs from 'fs';
import * as path from 'path';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'DatasetBuilder' });
const prisma = new PrismaClient();

// ─── Constants ──────────────────────────────────────────────────────────────

const DATASETS_DIR = path.resolve(process.cwd(), 'datasets');
const MAX_RECORDS_PER_EXPORT = 50_000;

// ─── Types ──────────────────────────────────────────────────────────────────

export interface DatasetRecord {
    endpoint: string;
    parameters: string[];
    attackType: string;
    payload: string;
    responseSummary: string;
    result: string;
    confidence: number;
}

export interface ExportResult {
    filePath: string;
    recordCount: number;
    scanId: string | null;
    durationMs: number;
}

// ─── Sensitive Patterns ─────────────────────────────────────────────────────

const SENSITIVE_PATTERNS: RegExp[] = [
    /cookie\s*[:=]\s*[^\s;,}]{4,}/gi,
    /session\s*[:=]\s*[^\s;,}]{4,}/gi,
    /token\s*[:=]\s*[^\s;,}]{4,}/gi,
    /bearer\s+[a-zA-Z0-9._-]{10,}/gi,
    /password\s*[:=]\s*[^\s;,}]{2,}/gi,
    /passwd\s*[:=]\s*[^\s;,}]{2,}/gi,
    /api[_-]?key\s*[:=]\s*[^\s;,}]{8,}/gi,
    /secret\s*[:=]\s*[^\s;,}]{8,}/gi,
    /authorization\s*[:=]\s*[^\s;,}]{8,}/gi,
    /AKIA[A-Z0-9]{16}/g,
    /AIza[a-zA-Z0-9_-]{35}/g,
    /(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{20,}/g,
    /gh[pousr]_[a-zA-Z0-9]{36,}/g,
    /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g,
];

// ─── Service ────────────────────────────────────────────────────────────────

export class DatasetBuilder {
    /**
     * Export dataset for a single scan.
     */
    async exportScanDataset(scanId: string): Promise<ExportResult> {
        const start = Date.now();
        this.ensureDir();

        const findings = await prisma.finding.findMany({
            where: { scanId },
            take: MAX_RECORDS_PER_EXPORT,
            include: { endpoint: true },
        });

        const records: DatasetRecord[] = [];

        for (const finding of findings) {
            const params = this.extractParams(finding.endpoint?.params ?? '[]');
            const record: DatasetRecord = {
                endpoint: this.sanitizeData(finding.url),
                parameters: params,
                attackType: finding.type,
                payload: this.sanitizeData(finding.evidence.slice(0, 500)),
                responseSummary: this.sanitizeData(finding.description.slice(0, 300)),
                result: finding.severity,
                confidence: this.severityToConfidence(finding.severity),
            };
            records.push(record);
        }

        const fileName = `scan-${scanId}.jsonl`;
        const filePath = path.join(DATASETS_DIR, fileName);

        const lines = records.map(r => JSON.stringify(r)).join('\n');
        fs.writeFileSync(filePath, lines + '\n', 'utf-8');

        log.info('Scan dataset exported', {
            scanId,
            records: records.length,
            filePath,
            durationMs: Date.now() - start,
        });

        return {
            filePath,
            recordCount: records.length,
            scanId,
            durationMs: Date.now() - start,
        };
    }

    /**
     * Export global dataset across all scans.
     */
    async exportGlobalDataset(): Promise<ExportResult> {
        const start = Date.now();
        this.ensureDir();

        const findings = await prisma.finding.findMany({
            take: MAX_RECORDS_PER_EXPORT,
            include: { endpoint: true },
            orderBy: { createdAt: 'desc' },
        });

        const records: DatasetRecord[] = [];

        for (const finding of findings) {
            const params = this.extractParams(finding.endpoint?.params ?? '[]');
            const record: DatasetRecord = {
                endpoint: this.sanitizeData(finding.url),
                parameters: params,
                attackType: finding.type,
                payload: this.sanitizeData(finding.evidence.slice(0, 500)),
                responseSummary: this.sanitizeData(finding.description.slice(0, 300)),
                result: finding.severity,
                confidence: this.severityToConfidence(finding.severity),
            };
            records.push(record);
        }

        const fileName = `global-dataset.jsonl`;
        const filePath = path.join(DATASETS_DIR, fileName);

        const lines = records.map(r => JSON.stringify(r)).join('\n');
        fs.writeFileSync(filePath, lines + '\n', 'utf-8');

        log.info('Global dataset exported', {
            records: records.length,
            filePath,
            durationMs: Date.now() - start,
        });

        return {
            filePath,
            recordCount: records.length,
            scanId: null,
            durationMs: Date.now() - start,
        };
    }

    /**
     * Sanitize a string by removing sensitive data patterns.
     * Replaces matched patterns with [REDACTED].
     */
    sanitizeData(input: string): string {
        let sanitized = input;
        for (const pattern of SENSITIVE_PATTERNS) {
            pattern.lastIndex = 0;
            sanitized = sanitized.replace(pattern, '[REDACTED]');
        }
        return sanitized;
    }

    // ─── Helpers ──────────────────────────────────────────────────────────

    private ensureDir(): void {
        if (!fs.existsSync(DATASETS_DIR)) {
            fs.mkdirSync(DATASETS_DIR, { recursive: true });
        }
    }

    private extractParams(paramsJson: string): string[] {
        try {
            const parsed = JSON.parse(paramsJson);
            if (Array.isArray(parsed)) {
                return parsed.map(String).slice(0, 50);
            }
            return [];
        } catch {
            return [];
        }
    }

    private severityToConfidence(severity: string): number {
        switch (severity.toLowerCase()) {
            case 'critical': return 0.95;
            case 'high': return 0.8;
            case 'medium': return 0.6;
            case 'low': return 0.4;
            default: return 0.3;
        }
    }
}
