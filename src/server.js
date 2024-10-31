import express from 'express';
import { createServer } from 'node:http';
import { Server } from 'socket.io';

import { subtle } from 'node:crypto';

// Note: used https://github.com/socketio/chat-example/ (MIT, 2024) as a starting point.

// Smash Messaging Endpoint (websockets) 0.0.1 

// GOALS
// - [x] register anonymous users with any public key
// - [x] authenticate registers with private key challenge
// - [x] accept messages from any peer towards registered public key
// - [-] reject messages peer not found
// - [x] relay messages to the public key recipient (connected)
// - [x] async (offline)
// - [ ] 
// NON GOALS
// - scaling (horizontal scale coordinating multiple nodes)
// - authentication (ACL/usage)
// - one-time keys
// - multi-thread optimisation (like that or one thread per client(?)-TODO read about it)—vertical scale
// - non-websocket support
// - webRTC upgrade
// - http endpoint (vs websocket , pour lazy post for non-paired users)
// - 


const ENCODING = "base64";
const EXPORTABLE = "spki";
const exportKey = async (key, encoding = ENCODING) => (
  Buffer.from(await subtle.exportKey(EXPORTABLE, key)).toString(encoding)
);
const importKey = async (keyEncoded, keyAlgorithm, exportable = true, usages = [], encoding = ENCODING) => (
  await subtle.importKey(EXPORTABLE,
    Buffer.from(keyEncoded, encoding),
    keyAlgorithm,
    exportable,
    usages,
  )
);
const importClientPublicKey = async (socket) => (await importKey(socket.handshake.auth.key, socket.handshake.auth.keyAlgorithm));
export const last4 = (str) => str.substring(str.length - 6, str.length - 2);

async function start() {
  const app = express();
  const server = createServer(app);
  const io = new Server(server);
  const port = process.env.PORT || 3210;

  // TODO: reimplement in TypeScript

  const REGISTERED_USERS = {}; // {socket?, queue: []}

  const sendDataTo = (keyId, sessionId, data) => {
    REGISTERED_USERS[keyId]?.queue.push([sessionId, data]);
    flushDataQueue(keyId);
  };

  const flushDataQueue = (keyId) => {
    const recipient = REGISTERED_USERS[keyId];
    if (recipient.socket) while (recipient.queue.length) {
      // TODO only remove from queue if successful!!
      const [sessionId, data] = recipient.queue.shift();
      recipient.socket.emit('data', sessionId, data);
      console.log(`> Sent data for ${last4(keyId)} (length: ${data.length}, session: ${sessionId})`);
    }
  }

  const registerMailBox = (keyId, recipientSocket) => {
    const alreadyRegistered = !!Object.hasOwn(REGISTERED_USERS, keyId);
    if (alreadyRegistered) {
      REGISTERED_USERS[keyId].socket = recipientSocket;
      flushDataQueue(keyId);
    }
    else {
      REGISTERED_USERS[keyId] = { socket: recipientSocket, queue: [] };
    }
    console.log(`>>> Successfully ${alreadyRegistered ? "updated" : "registered"} ${last4(keyId)} mailbox/socket`);
  }

  // connect
  // connect_error
  // disconnect
  // disconnecting
  // newListener
  // removeListener

  const KEY_ALGORITHM = { name: "ECDH", namedCurve: "P-256" };
  const KEY_USAGE = ['deriveBits', 'deriveKey'];

  // // Generate an extractable Elliptic Curve Diffie - Hellman keypair
  // const SME_KEY_PAIR = await subtle.generateKey(KEY_ALGORITHM, true, KEY_USAGE);
  // console.log(`Preparing to export keys: ${SME_KEY_PAIR.publicKey.extractable} ${SME_KEY_PAIR.privateKey.extractable}`);
  // const exportedSmePublicKey = await subtle.exportKey("jwk", SME_KEY_PAIR.publicKey);
  // const exportedSmePrivateKey = await subtle.exportKey("jwk", SME_KEY_PAIR.privateKey);
  // // TODO Generate key pair once and store in config + load from ENV at boot
  // console.log('SME Private Key', JSON.stringify(exportedSmePrivateKey));
  // console.log('SME Public Key', JSON.stringify(exportedSmePublicKey));
  // process.exit();

  const exportedSmePrivateKey = JSON.parse('{"key_ops":["deriveKey","deriveBits"],"ext":true,"kty":"EC","x":"Xg8dSsr93TMctKPiG3yRZ72KTJihrzSTzE_vLk7m1to","y":"cJg1q3Mk08b_gw7pawTB9oZ2svkZE_6I0C26ZDJC0Qk","crv":"P-256","d":"ObBoSrita5E2pJXQOTC35amrY-8bTRq1SdbDFmawkDU"}');
  const exportedSmePublicKey = JSON.parse('{"key_ops":[],"ext":true,"kty":"EC","x":"Xg8dSsr93TMctKPiG3yRZ72KTJihrzSTzE_vLk7m1to","y":"cJg1q3Mk08b_gw7pawTB9oZ2svkZE_6I0C26ZDJC0Qk","crv":"P-256"}');
  const SME_KEY_PAIR = {
    publicKey: await subtle.importKey("jwk", exportedSmePublicKey, KEY_ALGORITHM, true, []),
    privateKey: await subtle.importKey("jwk", exportedSmePrivateKey, KEY_ALGORITHM, false, KEY_USAGE),
  };

  console.log("\n**** SME CONFIG ***");
  const SME_CONFIG = {
    url: `ws://host.docker.internal:${port}/`,
    smePublicKey: await exportKey(SME_KEY_PAIR.publicKey),
    keyAlgorithm: SME_KEY_PAIR.publicKey.algorithm,
    encryptionAlgorithm: {
      name: "AES-GCM",
      length: 256,
    },
    challengeEncoding: "base64",
  }
  console.log(JSON.stringify(SME_CONFIG));
  console.log("\n\n");

  // challenge the new user on connection attempt
  io.use(async (socket, next) => {
    try {
      next();
    } catch {
      console.log('attempting to connect without PK');
      next(new Error("No valid Public Key could be retrieved / Challenge couldn't be sent."));
    }
  });

  io.on('connection', async (socket) => {
    const auth = !!socket.handshake.auth.key;
    const clientPublicKey = auth ? await importClientPublicKey(socket) : undefined;
    // Generate a Base64 encoding of the Client public key
    const clientKeyId = auth ? await exportKey(clientPublicKey) : "ANONYMOUS";

    socket.on('data', (peerId, sessionId, data) => {
      if (!Object.hasOwn(REGISTERED_USERS, peerId)) {
        console.error(`unknown peer id ${last4(peerId)}`);
        // TODO 404 to user
      } else {
        console.log(`>>> Incoming data for ${last4(peerId)} (length: ${data.length}, session: ${sessionId})`);
        sendDataTo(peerId, sessionId, data);
      }
    });

    if (!socket.recovered && auth) {
      // unique stuff should be done here
      console.log('> connected', last4(clientKeyId));
      // A new shared AES-GCM encryption / decryption key is generated for challenge encryption
      // The server's private key is used as the "key", the client's public key is used as "public".
      // This is computed separately by both parties and the result is always the same.
      const symKey = await subtle.deriveKey({
        ...socket.handshake.auth.keyAlgorithm,
        public: clientPublicKey,
      }, SME_KEY_PAIR.privateKey, SME_CONFIG.encryptionAlgorithm, false, ['encrypt', 'decrypt']);

      // A random iv is generated and used for encryption
      const iv = crypto.getRandomValues(new Uint8Array(12));
      // A random challenge is generated, used, and stored for access-token-based authentication
      // TODO: store and compare
      const challenge = crypto.getRandomValues(new Uint8Array(12));

      const ivBuf = Buffer.from(iv);
      const challengeBuf = Buffer.from(challenge);

      // The iv and the message are used to create an encrypted series of bits.
      const encryptedChallenge = await subtle.encrypt({
        ...SME_CONFIG.encryptionAlgorithm,
        iv: iv
      }, symKey, challengeBuf);

      const encryptedChallengeBuf = Buffer.from(encryptedChallenge);

      socket.on('register', async solvedChallengeAsString => {
        if (solvedChallengeAsString === challengeBuf.toString(SME_CONFIG.challengeEncoding)) {
          // Register a mailbox if not already registered
          registerMailBox(clientKeyId, socket);
        } else {
          // TODO: better cleaner scalable logs
          console.warn('!!! FAILED CHALLENGE !!!');
          socket.disconnect(true);
        }
        console.log('\nALL MAILBOXES:', JSON.stringify(Object.keys(REGISTERED_USERS).map(k => `${last4(k)}: ${k}`), null, 2), '\n');
      });

      socket.emit('challenge', {
        iv: ivBuf.toString(SME_CONFIG.challengeEncoding),
        challenge: encryptedChallengeBuf.toString(SME_CONFIG.challengeEncoding),
      })
      console.log('> challenged', last4(clientKeyId));
    } else {
      console.log('>>> re-connected', last4(clientKeyId));
    }

    socket.on('disconnect', () => {
      console.log('>>> disconnected', last4(clientKeyId));
      if (REGISTERED_USERS[clientKeyId]) REGISTERED_USERS[clientKeyId].socket = undefined;
    });
  });

  // app.post("/m/:keyEncoded", async (req, res) => {
  //   console.log(`new message for ${req.params.keyEncoded}`);
  //   console.log(req.body);
  //   res.send();
  // });

  server.listen(port, () => {
    console.log(`server running at http://localhost:${port}`);
  });

}

start()
