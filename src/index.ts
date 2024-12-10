import { start } from './server.js';

// Initialize SME key pair
const exportedSmePrivateKey = JSON.parse(
    '{"key_ops":["deriveKey","deriveBits"],"ext":true,"kty":"EC","x":"Xg8dSsr93TMctKPiG3yRZ72KTJihrzSTzE_vLk7m1to","y":"cJg1q3Mk08b_gw7pawTB9oZ2svkZE_6I0C26ZDJC0Qk","crv":"P-256","d":"ObBoSrita5E2pJXQOTC35amrY-8bTRq1SdbDFmawkDU"}',
);
const exportedSmePublicKey = JSON.parse(
    '{"key_ops":[],"ext":true,"kty":"EC","x":"Xg8dSsr93TMctKPiG3yRZ72KTJihrzSTzE_vLk7m1to","y":"cJg1q3Mk08b_gw7pawTB9oZ2svkZE_6I0C26ZDJC0Qk","crv":"P-256"}',
);

start(exportedSmePublicKey, exportedSmePrivateKey).catch(console.error);
