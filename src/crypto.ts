import { Buffer } from 'node:buffer';
import { subtle } from 'node:crypto';

export const ENCODING = 'base64' as const;
export const EXPORTABLE = 'spki' as const;

export const exportKey = async (
    key: CryptoKey,
    encoding: BufferEncoding = ENCODING,
    format: KeyFormat = EXPORTABLE,
): Promise<string> =>
    Buffer.from(
        await subtle.exportKey(format as 'spki' | 'pkcs8' | 'raw', key),
    ).toString(encoding);

export const importKey = async (
    keyEncoded: string,
    keyAlgorithm: EcKeyAlgorithm,
    exportable = true,
    usages: KeyUsage[] = [],
    encoding: BufferEncoding = ENCODING,
    format: KeyFormat = EXPORTABLE,
): Promise<CryptoKey> =>
    await subtle.importKey(
        format as 'spki' | 'pkcs8' | 'raw',
        Buffer.from(keyEncoded, encoding),
        keyAlgorithm,
        exportable,
        usages,
    );

export const last4 = (str: string): string => {
    const trimmed = str.replaceAll('=', '');
    return trimmed.substring(trimmed.length - 4, trimmed.length);
};
