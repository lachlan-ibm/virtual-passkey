/**
 * CBOR encoding utilities for WebAuthn
 * Implements WebAuthn-compliant CBOR: no type hints, fixed lengths, sorted keys
 */
export class CBOREncoder {
  private buffer: number[] = [];

  /**
   * Encode a value to CBOR
   */
  encode(value: any): Uint8Array {
    this.buffer = [];
    this.encodeValue(value);
    return new Uint8Array(this.buffer);
  }

  private encodeValue(value: any): void {
    if (value === null || value === undefined) {
      this.buffer.push(0xf6); // null
    } else if (typeof value === 'boolean') {
      this.buffer.push(value ? 0xf5 : 0xf4);
    } else if (typeof value === 'number') {
      this.encodeNumber(value);
    } else if (typeof value === 'string') {
      this.encodeString(value);
    } else if (value instanceof Uint8Array || Buffer.isBuffer(value)) {
      this.encodeByteString(value);
    } else if (Array.isArray(value)) {
      this.encodeArray(value);
    } else if (typeof value === 'object') {
      this.encodeMap(value);
    }
  }

  private encodeNumber(value: number): void {
    if (Number.isInteger(value)) {
      if (value >= 0) {
        // Positive integer
        if (value < 24) {
          this.buffer.push(value);
        } else if (value < 256) {
          this.buffer.push(0x18, value);
        } else if (value < 65536) {
          this.buffer.push(0x19, value >> 8, value & 0xff);
        } else {
          this.buffer.push(0x1a, 
            (value >> 24) & 0xff, (value >> 16) & 0xff, 
            (value >> 8) & 0xff, value & 0xff);
        }
      } else {
        // Negative integer
        const positive = -1 - value;
        if (positive < 24) {
          this.buffer.push(0x20 | positive);
        } else if (positive < 256) {
          this.buffer.push(0x38, positive);
        } else if (positive < 65536) {
          this.buffer.push(0x39, positive >> 8, positive & 0xff);
        } else {
          this.buffer.push(0x3a,
            (positive >> 24) & 0xff, (positive >> 16) & 0xff,
            (positive >> 8) & 0xff, positive & 0xff);
        }
      }
    }
  }

  private encodeString(value: string): void {
    const utf8 = Buffer.from(value, 'utf8');
    const length = utf8.length;
    
    // Major type 3: text string
    if (length < 24) {
      this.buffer.push(0x60 | length);
    } else if (length < 256) {
      this.buffer.push(0x78, length);
    } else if (length < 65536) {
      this.buffer.push(0x79, length >> 8, length & 0xff);
    } else {
      this.buffer.push(0x7a,
        (length >> 24) & 0xff, (length >> 16) & 0xff,
        (length >> 8) & 0xff, length & 0xff);
    }
    this.buffer.push(...utf8);
  }

  private encodeByteString(value: Uint8Array | Buffer): void {
    const length = value.length;
    
    // Major type 2: byte string
    if (length < 24) {
      this.buffer.push(0x40 | length);
    } else if (length < 256) {
      this.buffer.push(0x58, length);
    } else if (length < 65536) {
      this.buffer.push(0x59, length >> 8, length & 0xff);
    } else {
      this.buffer.push(0x5a,
        (length >> 24) & 0xff, (length >> 16) & 0xff,
        (length >> 8) & 0xff, length & 0xff);
    }
    this.buffer.push(...value);
  }

  private encodeArray(value: any[]): void {
    const length = value.length;
    
    // Major type 4: array - fixed length
    if (length < 24) {
      this.buffer.push(0x80 | length);
    } else if (length < 256) {
      this.buffer.push(0x98, length);
    } else if (length < 65536) {
      this.buffer.push(0x99, length >> 8, length & 0xff);
    } else {
      this.buffer.push(0x9a,
        (length >> 24) & 0xff, (length >> 16) & 0xff,
        (length >> 8) & 0xff, length & 0xff);
    }
    
    for (const item of value) {
      this.encodeValue(item);
    }
  }

  private encodeMap(value: Record<string, any>): void {
    // Sort keys lexicographically for WebAuthn compliance
    const entries = Object.entries(value).sort((a, b) => {
      const aKey = typeof a[0] === 'string' ? a[0] : String(a[0]);
      const bKey = typeof b[0] === 'string' ? b[0] : String(b[0]);
      return aKey.localeCompare(bKey);
    });
    
    const length = entries.length;
    
    // Major type 5: map - fixed length
    if (length < 24) {
      this.buffer.push(0xa0 | length);
    } else if (length < 256) {
      this.buffer.push(0xb8, length);
    } else if (length < 65536) {
      this.buffer.push(0xb9, length >> 8, length & 0xff);
    } else {
      this.buffer.push(0xba,
        (length >> 24) & 0xff, (length >> 16) & 0xff,
        (length >> 8) & 0xff, length & 0xff);
    }
    
    for (const [key, val] of entries) {
      this.encodeValue(key);
      this.encodeValue(val);
    }
  }
}


// Made with Bob
