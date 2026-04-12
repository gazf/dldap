/**
 * BER (Basic Encoding Rules) decoder for ASN.1 structures used in LDAP.
 *
 * Each TLV (Tag-Length-Value) element is decoded into a BerElement.
 */

export interface BerElement {
  /** Raw tag byte */
  tag: number;
  /** Tag class: 0=universal, 1=application, 2=context, 3=private */
  tagClass: number;
  /** Whether this is a constructed element (contains sub-elements) */
  constructed: boolean;
  /** Tag number within the class */
  tagNumber: number;
  /** Raw value bytes */
  value: Uint8Array;
}

/**
 * Decode all top-level BER elements from a buffer.
 * Returns decoded elements and number of bytes consumed.
 */
export function decodeBer(buf: Uint8Array, offset = 0): { element: BerElement; bytesRead: number } {
  if (offset >= buf.length) {
    throw new Error("BER decode: unexpected end of buffer");
  }

  const tagByte = buf[offset];
  const tagClass = (tagByte & 0xc0) >> 6;
  const constructed = (tagByte & 0x20) !== 0;
  let tagNumber = tagByte & 0x1f;
  let pos = offset + 1;

  // Long-form tag number
  if (tagNumber === 0x1f) {
    tagNumber = 0;
    while (pos < buf.length) {
      const b = buf[pos++];
      tagNumber = (tagNumber << 7) | (b & 0x7f);
      if ((b & 0x80) === 0) break;
    }
  }

  // Decode length
  if (pos >= buf.length) {
    throw new Error("BER decode: unexpected end of buffer reading length");
  }
  const firstLenByte = buf[pos++];
  let length: number;

  if (firstLenByte < 0x80) {
    length = firstLenByte;
  } else {
    const numBytes = firstLenByte & 0x7f;
    if (numBytes === 0) {
      throw new Error("BER decode: indefinite length not supported");
    }
    length = 0;
    for (let i = 0; i < numBytes; i++) {
      if (pos >= buf.length) {
        throw new Error("BER decode: unexpected end of buffer reading long length");
      }
      length = (length << 8) | buf[pos++];
    }
  }

  if (pos + length > buf.length) {
    throw new Error(
      `BER decode: value length ${length} exceeds buffer (at offset ${pos}, buf.length=${buf.length})`,
    );
  }

  const value = buf.slice(pos, pos + length);
  const bytesRead = pos + length - offset;

  return {
    element: { tag: tagByte, tagClass, constructed, tagNumber, value },
    bytesRead,
  };
}

/** Decode multiple sequential BER elements from a buffer. */
export function decodeAll(buf: Uint8Array): BerElement[] {
  const elements: BerElement[] = [];
  let offset = 0;
  while (offset < buf.length) {
    const { element, bytesRead } = decodeBer(buf, offset);
    elements.push(element);
    offset += bytesRead;
  }
  return elements;
}

/** Decode children of a constructed BER element. */
export function decodeChildren(element: BerElement): BerElement[] {
  if (!element.constructed) {
    throw new Error("BER decode: cannot decode children of primitive element");
  }
  return decodeAll(element.value);
}

// --- Primitive value decoders ---

export function decodeInteger(element: BerElement): number {
  let value = 0;
  const bytes = element.value;
  if (bytes.length === 0) return 0;
  // Handle sign
  const negative = (bytes[0] & 0x80) !== 0;
  for (const byte of bytes) {
    value = (value << 8) | byte;
  }
  if (negative && bytes.length < 4) {
    value |= ~((1 << (bytes.length * 8)) - 1);
  }
  return value;
}

export function decodeOctetString(element: BerElement): Uint8Array {
  return element.value;
}

export function decodeOctetStringAsString(element: BerElement): string {
  return new TextDecoder().decode(element.value);
}

export function decodeBoolean(element: BerElement): boolean {
  return element.value[0] !== 0;
}

/** Decode enumerated value (same encoding as integer in BER) */
export function decodeEnumerated(element: BerElement): number {
  return decodeInteger(element);
}
