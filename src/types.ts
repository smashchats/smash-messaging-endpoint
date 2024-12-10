import { Socket } from 'socket.io';

export interface RegisteredUser {
    socket?: Socket;
    queue: [string, {length: number}][];
}

export interface RegisteredUsers {
    [key: string]: RegisteredUser;
}

export interface KeyPair {
    publicKey: CryptoKey;
    privateKey: CryptoKey;
}

export interface SMEConfig {
    url: string;
    smePublicKey: string;
    keyAlgorithm: EcKeyAlgorithm;
    encryptionAlgorithm: AesKeyAlgorithm;
    challengeEncoding: BufferEncoding;
}

export interface ChallengeResponse {
    iv: string;
    challenge: string;
}
