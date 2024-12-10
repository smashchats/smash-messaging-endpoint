import { subtle } from 'crypto';
import { io as Client, Socket } from 'socket.io-client';

import { exportKey, importKey } from '../src/crypto';
import { KEY_ALGORITHM, KEY_USAGES, start } from '../src/server';

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const ENCRYPTION_ALGORITHM = {
    name: 'AES-GCM',
    length: 256,
};

interface ChallengeData {
    iv: string;
    challenge: string;
}

class AuthenticatedClient {
    socket?: Socket;
    keyPair?: CryptoKeyPair;
    exportedPublicKey?: string;

    async connect(url: string, smePublicKey: string) {
        this.keyPair = await subtle.generateKey(
            KEY_ALGORITHM,
            true,
            KEY_USAGES,
        );
        this.exportedPublicKey = await exportKey(this.keyPair.publicKey);
        this.socket = Client(url, {
            auth: {
                key: this.exportedPublicKey,
                keyAlgorithm: KEY_ALGORITHM,
            },
        });
        this.socket.on('challenge', async (data: ChallengeData) => {
            await this.solveChallenge(smePublicKey, data);
        });
    }

    async solveChallenge(smePublicKeyString: string, data: ChallengeData) {
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
                return start(keys.publicKey, keys.privateKey);
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

    it('should handle anonymous connections', (done) => {
        const clientSocket = Client(URL);
        clientSocket.on('connect', () => {
            expect(clientSocket.connected).toBeTruthy();
            done();
        });
    });

    it('should handle authenticated connection and challenge', async () => {
        client = new AuthenticatedClient();
        await client.connect(URL, smePublicKey);
        await sleep(500);
        const socket = client.getSocket();
        expect(socket.connected).toBeTruthy();
    });

    it('should fail authentication with incorrect challenge solution', async () => {
        client = new AuthenticatedClient();

        // Override solveChallenge to return incorrect solution
        jest.spyOn(
            client as AuthenticatedClient,
            'solveChallenge',
        ).mockImplementation(async function (this: AuthenticatedClient) {
            this.socket!.emit('register', 'incorrect_solution');
        });

        await client.connect(URL, smePublicKey);
        await sleep(500);

        const socket = client.getSocket();
        expect(socket.connected).toBeFalsy();
    });

    describe('message passing between clients', () => {
        let sender: AuthenticatedClient;
        let receiver: AuthenticatedClient;

        beforeEach(async () => {
            // Set up two authenticated clients
            sender = new AuthenticatedClient();
            receiver = new AuthenticatedClient();

            await sender.connect(URL, smePublicKey);
            await receiver.connect(URL, smePublicKey);
            await sleep(500); // Wait for authentication to complete
        });

        afterEach(() => {
            sender.disconnect();
            receiver.disconnect();
        });

        it('should successfully pass messages between authenticated clients', (done) => {
            const testMessage = { length: 42 };
            const testSessionId = 'test-session';

            // Set up receiver to listen for data
            receiver.getSocket().on('data', (sessionId, data) => {
                expect(sessionId).toBe(testSessionId);
                expect(data).toEqual(testMessage);
                done();
            });

            // Get receiver's public key
            const receiverPublicKey = receiver.exportedPublicKey;

            // Send message from sender to receiver
            sender
                .getSocket()
                .emit('data', receiverPublicKey, testSessionId, testMessage);
        });

        it('should handle messages to non-existent peers', (done) => {
            const testMessage = { length: 42 };
            const testSessionId = 'test-session';
            const nonExistentPeerId = 'non-existent-peer-id';

            sender.getSocket().on('error', (error) => {
                expect(error.code).toBe(404);
                expect(error.message).toContain('Peer');
                expect(error.message).toContain('not found');
                done();
            });

            sender
                .getSocket()
                .emit('data', nonExistentPeerId, testSessionId, testMessage);
        });
    });
});
