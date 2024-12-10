import { subtle } from 'crypto';
import { io as Client, Socket } from 'socket.io-client';

import { exportKey, importKey } from '../src/crypto';
import { start } from '../src/server';

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const KEY_ALGORITHM: EcKeyAlgorithm = {
    name: 'ECDH',
    namedCurve: 'P-256',
};

const ENCRYPTION_ALGORITHM = {
    name: 'AES-GCM',
    length: 256,
};

interface ChallengeData {
    iv: string;
    challenge: string;
}

class AuthenticatedClient {
    private socket?: Socket;
    private keyPair?: CryptoKeyPair;

    async connect(url: string, smePublicKey: string) {
        this.keyPair = await subtle.generateKey(KEY_ALGORITHM, true, [
            'deriveKey',
            'deriveBits',
        ]);
        const exportedPublicKey = await exportKey(this.keyPair.publicKey);
        this.socket = Client(url, {
            auth: {
                key: exportedPublicKey,
                keyAlgorithm: KEY_ALGORITHM,
            },
        });
        this.socket.on('challenge', async (data: ChallengeData) => {
            await this.solveChallenge(smePublicKey, data);
        });
    }

    private async solveChallenge(
        smePublicKeyString: string,
        data: ChallengeData,
    ) {
        try {
            // Convert base64 strings to buffers
            const ivBuffer = Buffer.from(data.iv, 'base64');
            const challengeBuffer = Buffer.from(data.challenge, 'base64');

            // Import the SME public key
            const smePublicKey = await importKey(
                smePublicKeyString,
                KEY_ALGORITHM,
                true,
                [],
            );

            // Derive the symmetric key
            const symmetricKey = await subtle.deriveKey(
                {
                    ...KEY_ALGORITHM,
                    public: smePublicKey,
                },
                this.keyPair!.privateKey,
                ENCRYPTION_ALGORITHM,
                false,
                ['decrypt'],
            );

            // Decrypt the challenge
            const decrypted = await subtle.decrypt(
                {
                    ...ENCRYPTION_ALGORITHM,
                    iv: ivBuffer,
                },
                symmetricKey,
                challengeBuffer,
            );

            // Convert the decrypted buffer to base64
            const solvedChallenge = Buffer.from(decrypted).toString('base64');

            // Send the solution
            this.socket!.emit('register', solvedChallenge);
        } catch (err) {
            console.error('Failed to solve challenge:', err);
            throw err;
        }
    }

    public getSocket(): Socket {
        return this.socket!;
    }

    public disconnect() {
        this.socket?.disconnect();
    }
}

describe('SME Server', () => {
    const PORT = 3211;
    const HOST = 'localhost';
    const URL = `ws://${HOST}:${PORT}`;
    let server: { close: () => void };
    let client: AuthenticatedClient;

    let smePublicKey: string;

    beforeAll((done) => {
        process.env.PORT = PORT.toString();
        process.env.HOST = HOST;
        crypto.subtle
            .generateKey(KEY_ALGORITHM, true, ['deriveKey', 'deriveBits'])
            .then((keys) => {
                exportKey(keys.publicKey).then((keyString) => {
                    smePublicKey = keyString;
                });
                return Promise.all([
                    crypto.subtle.exportKey('jwk', keys.publicKey),
                    crypto.subtle.exportKey('jwk', keys.privateKey),
                ]);
            })
            .then(([publicKey, privateKey]) => {
                return start(publicKey, privateKey);
            })
            .then((newServer) => {
                server = newServer;
                done();
            });
    });

    afterAll(async () => {
        server.close();
        await sleep(1000);
    });

    afterEach(() => {
        if (client) {
            client.disconnect();
        }
    });

    it('should respond to health check', async () => {
        const response = await fetch(`http://${HOST}:${PORT}/health`);
        const data = await response.json();
        expect(response.status).toBe(200);
        expect(data.status).toBe('healthy');
    });

    it('should handle authenticated connection and challenge', async () => {
        client = new AuthenticatedClient();
        await client.connect(URL, smePublicKey);
        await sleep(500);
        const socket = client.getSocket();
        expect(socket.connected).toBeTruthy();
    });

            // Listen for successful registration
            socket.on('data', () => {
                expect(socket.connected).toBeTruthy();
                done();
            });
        });
    });
});
