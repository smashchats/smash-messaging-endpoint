import { Socket } from 'socket.io-client';
import { start } from '../src/server';

describe('SME Server', () => {
    const PORT = 3211;
    const HOST = 'localhost';
    const URL = `ws://${HOST}:${PORT}`;
    let clientSocket: Socket;
    let server: any;

    beforeAll(async () => {
        // Import the server module dynamically since it's ESM
        process.env.PORT = PORT.toString();
        process.env.HOST = HOST;
        server = await start();
    });

    afterAll(async () => {
        if (clientSocket) {
            clientSocket.close();
        }
        server.close();
    });

    it('should respond to health check', async () => {
        const response = await fetch(`http://${HOST}:${PORT}/health`);
        const data = await response.json();
        expect(response.status).toBe(200);
        expect(data.status).toBe('healthy');
    });
}); 
