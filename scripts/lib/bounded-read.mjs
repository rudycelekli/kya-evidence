import { open } from 'node:fs/promises';
import { constants } from 'node:fs';

export const MAX_INPUT_BYTES = 2 * 1024 * 1024;

/**
 * Read an input file only when it is a regular file no larger than max. The size is taken from the open handle, so a path swapped after
 * the check cannot grow the read, and a FIFO or device is refused instead of waited on or read without end. Same call shape as readFile.
 */
export async function readBounded(path, encoding, max = MAX_INPUT_BYTES) {
  const handle = await open(path, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > max) throw new Error('Input must be a bounded regular file');
    const buffer = Buffer.alloc(stat.size);
    let filled = 0;
    while (filled < buffer.length) {
      const { bytesRead } = await handle.read(buffer, filled, buffer.length - filled, filled);
      if (bytesRead === 0) break;
      filled += bytesRead;
    }
    const bytes = buffer.subarray(0, filled);
    return encoding ? bytes.toString(encoding) : bytes;
  } finally { await handle.close(); }
}
