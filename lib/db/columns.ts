import { customType } from 'drizzle-orm/pg-core';

function toBytes(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) {
    return new Uint8Array(value);
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (typeof value === 'string') {
    // node-postgres / Neon may hand back bytea as "\xdeadbeef".
    const hex = value.startsWith('\\x') ? value.slice(2) : value;
    if (/^[0-9a-f]*$/i.test(hex) && hex.length % 2 === 0) {
      const out = new Uint8Array(hex.length / 2);
      for (let i = 0; i < out.length; i += 1) {
        out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
      }
      return out;
    }
  }
  if (Array.isArray(value)) {
    return Uint8Array.from(value);
  }
  throw new TypeError('Unsupported bytea value from database driver');
}

/**
 * PostgreSQL bytea, kept as Uint8Array in application code.
 * Both Neon HTTP and PGlite accept Uint8Array bind parameters.
 */
export const bytea = customType<{ data: Uint8Array; driverData: unknown }>({
  dataType() {
    return 'bytea';
  },
  toDriver(value) {
    return value;
  },
  fromDriver(value) {
    return toBytes(value);
  },
});
