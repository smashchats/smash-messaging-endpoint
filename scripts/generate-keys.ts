import { subtle } from 'crypto';

import { exportKey } from '../src/crypto';
import { KEY_ALGORITHM, KEY_USAGES } from '../src/server';

export async function generateKeys() {
    const keyPair = await subtle.generateKey(KEY_ALGORITHM, true, KEY_USAGES);
    if (!('publicKey' in keyPair && 'privateKey' in keyPair)) {
        throw new Error('Invalid key pair');
    }
    return Promise.all([
        exportKey(keyPair.publicKey),
        exportKey(keyPair.privateKey, 'base64', 'pkcs8'),
    ]);
}

generateKeys().then(([publicKey, privateKey]) => {
    console.log(`SME_PUBLIC_KEY="${publicKey}"`);
    console.log(`SME_PRIVATE_KEY="${privateKey}"`);
});
