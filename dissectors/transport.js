// Internal bytes survive packet spreading but are omitted by JSON/structured clone.
export const transportBytes = Symbol('transportBytes');
export const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
export function preview(result, bytes) {
  result.payloadLength = bytes.length;
  result.payloadPreview = hex(bytes.subarray(0, 256));
  if (bytes.length > 256) result.previewTruncated = true;
}
