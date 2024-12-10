import { subtle } from 'crypto';

import { exportKey, importKey, last4 } from '../src/crypto';

describe('Crypto Utils', () => {
    const KEY_ALGORITHM = {
        name: 'ECDH',
        namedCurve: 'P-256',
    };

    it('should export and import keys correctly', async () => {
        // Generate a test key pair
        const keyPair = await subtle.generateKey(KEY_ALGORITHM, true, [
            'deriveKey',
            'deriveBits',
        ]);

        // Test export
        const exportedKey = await exportKey(keyPair.publicKey);
        expect(exportedKey).toBeDefined();
        expect(typeof exportedKey).toBe('string');

        // Test import
        const importedKey = await importKey(
            exportedKey,
            KEY_ALGORITHM,
            true,
            [],
        );
        expect(importedKey).toBeDefined();
        expect(importedKey instanceof CryptoKey).toBeTruthy();
    });

    it('should handle invalid key import', async () => {
        await expect(
            importKey('invalid-key', KEY_ALGORITHM, true, ['deriveKey']),
        ).rejects.toThrow();
    });

    it('should return last 4 characters of string', () => {
        expect(last4('abcdefgh==')).toBe('efgh');
        expect(last4('abcdefgh=')).toBe('efgh');
        expect(last4('abcdefgh')).toBe('efgh');
        expect(last4('test==')).toBe('test');
        expect(last4('a==')).toBe('a');
        expect(last4('==')).toBe('');
    });
});
