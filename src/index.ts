import { importKey } from './crypto.js';
import { KEY_ALGORITHM, KEY_USAGES, start } from './server.js';

let server: { close: () => void };

async function startServer() {
    const publicKeyString = process.env.SME_PUBLIC_KEY;
    const privateKeyString = process.env.SME_PRIVATE_KEY;
    if (!publicKeyString || !privateKeyString) {
        throw new Error('SME_PUBLIC_KEY and SME_PRIVATE_KEY must be set');
    }
    const [publicKey, privateKey] = await Promise.all([
        importKey(
            publicKeyString,
            KEY_ALGORITHM as EcKeyAlgorithm,
            true,
            [],
            'base64',
            'spki',
        ),
        importKey(
            privateKeyString,
            KEY_ALGORITHM as EcKeyAlgorithm,
            true,
            KEY_USAGES,
            'base64',
            'pkcs8',
        ),
    ]);
    server = await start(publicKey, privateKey);
}

async function shutdown(signal: string) {
    console.log(`\nReceived ${signal}. Starting graceful shutdown...`);

    if (server) {
        try {
            await server.close();
            console.log('Server closed successfully');
        } catch (err) {
            console.error('Error while closing server:', err);
        }
    }

    process.exit(0);
}

// Handle shutdown signals
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

// Start the server and handle any errors
startServer().catch((err) => {
    console.error('Failed to start server:', err);
    process.exit(1);
});
