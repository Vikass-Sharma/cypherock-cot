import * as net from 'net';
import { FrameParser, createFrame } from './Framing';

/**
 * Clean, asynchronous TCP client using Node.js net module with framed communication.
 */
export class TcpClient {
    private socket: net.Socket | null = null;
    private parser: FrameParser = new FrameParser();
    private pendingFrames: Buffer[] = [];
    private waitingResolvers: Array<(frame: Buffer) => void> = [];
    private waitingRejecters: Array<(err: Error) => void> = [];
    private isClosed: boolean = false;

    constructor() {}

    /**
     * Connects to the TCP server at host:port.
     */
    public connect(host: string, port: number): Promise<void> {
        return new Promise((resolve, reject) => {
            const socket = new net.Socket();
            this.socket = socket;
            this.isClosed = false;

            socket.once('connect', () => {
                resolve();
            });

            socket.once('error', (err) => {
                reject(err);
            });

            socket.on('data', (chunk: Buffer) => {
                try {
                    const frames = this.parser.feed(chunk);
                    for (const frame of frames) {
                        if (this.waitingResolvers.length > 0) {
                            const res = this.waitingResolvers.shift()!;
                            this.waitingRejecters.shift();
                            res(frame);
                        } else {
                            this.pendingFrames.push(frame);
                        }
                    }
                } catch (err: any) {
                    this.failWaiting(err);
                    this.close();
                }
            });

            socket.on('close', () => {
                this.isClosed = true;
                this.failWaiting(new Error('Connection closed by remote peer'));
            });

            socket.on('error', (err) => {
                this.failWaiting(err);
            });

            socket.connect(port, host);
        });
    }

    /**
     * Sends a payload prefixed with 4-byte big-endian length.
     */
    public sendFrame(payload: Uint8Array): Promise<void> {
        return new Promise((resolve, reject) => {
            if (!this.socket || this.isClosed) {
                return reject(new Error('Socket is not connected'));
            }

            try {
                const frame = createFrame(payload);
                this.socket.write(frame, (err) => {
                    if (err) reject(err);
                    else resolve();
                });
            } catch (err) {
                reject(err);
            }
        });
    }

    /**
     * Awaits and receives the next complete framed payload.
     */
    public receiveFrame(): Promise<Buffer> {
        if (this.pendingFrames.length > 0) {
            return Promise.resolve(this.pendingFrames.shift()!);
        }

        if (this.isClosed) {
            return Promise.reject(new Error('Cannot receive frame: connection is closed'));
        }

        return new Promise((resolve, reject) => {
            this.waitingResolvers.push(resolve);
            this.waitingRejecters.push(reject);
        });
    }

    /**
     * Cleanly closes the TCP connection.
     */
    public close(): Promise<void> {
        return new Promise((resolve) => {
            if (!this.socket || this.isClosed) {
                this.isClosed = true;
                return resolve();
            }

            this.isClosed = true;
            this.socket.end(() => {
                this.socket?.destroy();
                resolve();
            });
        });
    }

    private failWaiting(err: Error): void {
        while (this.waitingRejecters.length > 0) {
            const rej = this.waitingRejecters.shift()!;
            this.waitingResolvers.shift();
            rej(err);
        }
    }
}
