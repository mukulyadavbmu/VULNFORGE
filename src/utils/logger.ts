import winston from 'winston';
import { config } from '../config';

const { combine, timestamp, json, colorize, printf, errors } = winston.format;

// Custom format for dev
const devFormat = printf(({ level, message, timestamp, stack, ...metadata }) => {
    let msg = `${timestamp} [${level}]: ${message}`;
    if (stack) msg += `\n${stack}`;
    if (Object.keys(metadata).length > 0) {
        msg += ` | ${JSON.stringify(metadata)}`;
    }
    return msg;
});

export const logger = winston.createLogger({
    level: config.NODE_ENV === 'production' ? 'info' : 'debug',
    format: combine(
        timestamp(),
        errors({ stack: true }), // Capture stack trace
        config.NODE_ENV === 'production' ? json() : combine(colorize(), devFormat)
    ),
    defaultMeta: { service: 'vulnforge-backend' },
    transports: [
        new winston.transports.Console(),
        // Add file transports here for production persistence if needed
    ],
});
