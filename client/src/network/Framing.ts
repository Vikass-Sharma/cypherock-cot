/**
 * 4-byte big-endian length-prefixed framing implementation.
 *
 * Framing Format:
 * [ 4-byte unsigned big-endian payload length ][ payload bytes ]
 */

export const MAX_FRAME_PAYLOAD_SIZE = 64 * 1024; // 64 KB
export const FRAME_HEADER_SIZE = 4;

/**
 * Creates a framed buffer: [4-byte uint32-be length][payload]
 */
export function createFrame(payload: Uint8Array): Buffer {
    if (payload.length > MAX_FRAME_PAYLOAD_SIZE) {
        throw new Error(
            `Payload size (${payload.length} bytes) exceeds MAX_FRAME_PAYLOAD_SIZE (${MAX_FRAME_PAYLOAD_SIZE} bytes)`
        );
    }

    const frame = Buffer.allocUnsafe(FRAME_HEADER_SIZE + payload.length);
    frame.writeUInt32BE(payload.length, 0);
    frame.set(payload, FRAME_HEADER_SIZE);
    return frame;
}

/**
 * Stream parser that accumulates incoming TCP data chunks and yields complete frames.
 * Handles split frames (partial TCP reads), concatenated frames (multiple frames in one chunk),
 * and rejects oversized frames.
 */
export class FrameParser {
    private buffer: Buffer = Buffer.alloc(0);

    /**
     * Feeds an arbitrary chunk of incoming bytes and extracts any complete frames.
     */
    public feed(chunk: Buffer): Buffer[] {
        if (!chunk || chunk.length === 0) {
            return [];
        }

        this.buffer = Buffer.concat([this.buffer, chunk]);
        const frames: Buffer[] = [];

        while (this.buffer.length >= FRAME_HEADER_SIZE) {
            const frameLen = this.buffer.readUInt32BE(0);

            if (frameLen > MAX_FRAME_PAYLOAD_SIZE) {
                this.buffer = Buffer.alloc(0);
                throw new Error(
                    `Frame length ${frameLen} exceeds MAX_FRAME_PAYLOAD_SIZE (${MAX_FRAME_PAYLOAD_SIZE})`
                );
            }

            if (this.buffer.length >= FRAME_HEADER_SIZE + frameLen) {
                const payload = this.buffer.subarray(FRAME_HEADER_SIZE, FRAME_HEADER_SIZE + frameLen);
                // Make an independent copy so modifications to buffer do not affect the returned payload
                frames.push(Buffer.from(payload));
                this.buffer = this.buffer.subarray(FRAME_HEADER_SIZE + frameLen);
            } else {
                // Incomplete frame, wait for subsequent chunks
                break;
            }
        }

        return frames;
    }

    /**
     * Returns true if there are unprocessed bytes in the buffer.
     */
    public hasPartialData(): boolean {
        return this.buffer.length > 0;
    }

    /**
     * Resets parser state.
     */
    public reset(): void {
        this.buffer = Buffer.alloc(0);
    }
}
