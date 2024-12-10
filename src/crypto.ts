import { Buffer } from 'node:buffer';
import { subtle } from 'node:crypto';

export const ENCODING = 'base64' as const;
export const EXPORTABLE = 'spki' as const;

export const exportKey = async (
    key: CryptoKey,
    encoding: BufferEncoding = ENCODING,
): Promise<string> =>
    Buffer.from(await subtle.exportKey(EXPORTABLE, key)).toString(encoding);

export const importKey = async (
    keyEncoded: string,
    keyAlgorithm: EcKeyAlgorithm,
    exportable = true,
    usages: KeyUsage[] = [],
    encoding: BufferEncoding = ENCODING,
): Promise<CryptoKey> =>
    await subtle.importKey(
        EXPORTABLE,
        Buffer.from(keyEncoded, encoding),
        keyAlgorithm,
        exportable,
        usages,
    );

export const last4 = (str: string): string =>
    str.substring(str.length - 6, str.length - 2);
