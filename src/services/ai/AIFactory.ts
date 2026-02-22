import { config } from '../../config';
import { AIProvider } from './types';
import { GeminiProvider } from './GeminiProvider';

export class AIFactory {
    static createProvider(): AIProvider {
        switch (config.AI_PROVIDER) {
            case 'gemini':
                return new GeminiProvider();
            case 'openai':
                throw new Error('OpenAI provider not yet implemented');
            case 'local':
                throw new Error('Local provider not yet implemented');
            default:
                return new GeminiProvider();
        }
    }
}
