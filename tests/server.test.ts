import { subtle } from 'crypto';
import { io as Client, Socket } from 'socket.io-client';

import { exportKey, importKey } from '../src/crypto';
import { Closable, KEY_ALGORITHM, KEY_USAGES, start } from '../src/server';

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

    async generateKeys() {
        this.keyPair = await subtle.generateKey(
            KEY_ALGORITHM,
            true,
            KEY_USAGES,
        );
        this.exportedPublicKey = await exportKey(this.keyPair.publicKey);
    }

    async connect(
        url: string,
        smePublicKey: string,
        ack?: (() => void) | undefined,
    ) {
        this.socket = Client(url, {
            auth: {
                key: this.exportedPublicKey,
                keyAlgorithm: KEY_ALGORITHM,
            },
            transports: ['websocket'],
        });
        this.socket.on('challenge', async (data: ChallengeData) => {
            await this.solveChallenge(smePublicKey, data, ack);
        });
    }

    async solveChallenge(
        smePublicKeyString: string,
        data: ChallengeData,
        ack: (() => void) | undefined,
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
            this.socket!.emit('register', solvedChallenge, ack);
        } catch (err) {
            console.error('Failed to solve challenge:', err);
            throw err;
        }
    }

    public getSocket(): Socket {
        return this.socket!;
    }

    public disconnect() {
        if (!this.socket) return;
        this.socket.removeAllListeners();
        this.socket.disconnect();
        this.socket.close();
        if (this.socket.io?.engine) {
            this.socket.io.engine.removeAllListeners();
            this.socket.io.engine.close();
            this.socket.io.engine.transport?.close();
        }
        this.socket = undefined;
    }
}

describe('SME Server', () => {
    const PORT = 3211;
    const HOST = 'localhost';
    const URL = `ws://${HOST}:${PORT}`;
    let server: Closable;
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
        await server.shutdown();
    }, 15000);

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
            clientSocket.disconnect();
            done();
        });
    });

    describe('for an authenticated client', () => {
        let client: AuthenticatedClient | undefined;

        beforeAll(async () => {
            client = new AuthenticatedClient();
            await client.generateKeys();
            await client.connect(URL, smePublicKey);
        });

        afterAll(async () => {
            client?.disconnect();
            await sleep(2000);
            client = undefined;
        });

        it('should handle authenticated connection and challenge', async () => {
            await sleep(500);
            const socket = client?.getSocket();
            expect(socket?.connected).toBeTruthy();
        });

        describe('reconnecting to the server', () => {
            it('should handle re-authentication', async () => {
                const socket = client?.getSocket();
                client?.disconnect();
                await sleep(500);
                expect(socket?.connected).toBeFalsy();
                await client?.connect(URL, smePublicKey);
                await sleep(500);
                const socket2 = client?.getSocket();
                expect(socket2?.connected).toBeTruthy();
            });
        });
    });

    describe('failure cases', () => {
        let client: AuthenticatedClient | undefined;

        beforeEach(async () => {
            client = new AuthenticatedClient();
            await client.generateKeys();
        });

        afterEach(async () => {
            client?.disconnect();
            await sleep(1000);
            client = undefined;
        });

        it('should fail authentication with incorrect challenge solution', async () => {
            if (!client) throw new Error('Client not found');
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

        it('should fail authentication with incorrect public key', async () => {
            if (!client) throw new Error('Client not found');

            client.exportedPublicKey = 'incorrect_public_key';
            await client.connect(URL, smePublicKey);
            await sleep(500);

            const socket = client.getSocket();
            expect(socket.connected).toBeFalsy();
        });
    });

    describe('message passing between clients', () => {
        let sender: AuthenticatedClient;
        let receiver: AuthenticatedClient;

        beforeEach(async () => {
            // Set up two authenticated clients
            sender = new AuthenticatedClient();
            receiver = new AuthenticatedClient();

            await sender.generateKeys();
            await receiver.generateKeys();

            await sender.connect(URL, smePublicKey);
            await receiver.connect(URL, smePublicKey);
            await sleep(500); // Wait for authentication to complete
        });

        afterEach(async () => {
            sender.disconnect();
            receiver.disconnect();
            await sleep(1000);
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

        describe('ACKnowledgements', () => {
            describe('challenge', () => {
                it('should ACK challenge on successful authentication', async () => {
                    let timeoutRef: NodeJS.Timeout | undefined;
                    const timeout = new Promise<void>((_, reject) => {
                        timeoutRef = setTimeout(
                            () => reject(new Error('Timeout waiting for ACK')),
                            3000,
                        );
                    });
                    await Promise.race([
                        new Promise<void>((resolve, reject) => {
                            sender
                                .connect(URL, smePublicKey, () => {
                                    clearTimeout(timeoutRef);
                                    resolve();
                                })
                                .then()
                                .catch(reject);
                        }),
                        timeout,
                    ]);
                });

                it('should NOT ACK challenge with incorrect challenge solution', async () => {
                    // Override solveChallenge to return incorrect solution
                    jest.spyOn(
                        sender as AuthenticatedClient,
                        'solveChallenge',
                    ).mockImplementation(async function (
                        this: AuthenticatedClient,
                    ) {
                        this.socket!.emit('register', 'incorrect_solution');
                    });
                    await Promise.race([
                        new Promise<void>((resolve, reject) => {
                            sender
                                .connect(URL, smePublicKey, reject)
                                .then()
                                .catch(resolve);
                        }),
                        new Promise<void>((resolve) =>
                            setTimeout(resolve, 3000),
                        ),
                    ]);
                });
            });

            describe('data', () => {
                it('should ACK data sent to an existing peer', async () => {
                    const testMessage = { length: 42 };
                    const testSessionId = 'test-session';
                    const receiverPublicKey = receiver.exportedPublicKey;
                    let timeoutRef: NodeJS.Timeout | undefined;
                    const timeout = new Promise<void>((_, reject) => {
                        timeoutRef = setTimeout(
                            () => reject(new Error('Timeout waiting for ACK')),
                            3000,
                        );
                    });
                    await Promise.race([
                        new Promise<void>((resolve) => {
                            sender
                                .getSocket()
                                .emit(
                                    'data',
                                    receiverPublicKey,
                                    testSessionId,
                                    testMessage,
                                    () => {
                                        clearTimeout(timeoutRef);
                                        resolve();
                                    },
                                );
                        }),
                        timeout,
                    ]);
                });

                it('should not ACK data sent to a non-existent peer', async () => {
                    const testMessage = { length: 42 };
                    const testSessionId = 'test-session';
                    const nonExistentPeerId = 'non-existent-peer-id';
                    await Promise.race([
                        new Promise<void>((_, reject) => {
                            sender
                                .getSocket()
                                .emit(
                                    'data',
                                    nonExistentPeerId,
                                    testSessionId,
                                    testMessage,
                                    reject,
                                );
                        }),
                        new Promise<void>((resolve) =>
                            setTimeout(resolve, 3000),
                        ),
                    ]);
                });
            });
        });
    });
});
