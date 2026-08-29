// Webhook receiver: the strict-equality signature check is the timing-leak
// shape; the timingSafeEqual variant below is the safe idiom.
import crypto from 'crypto';

const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET ?? '';

export function verifyWebhook(payload: string, header: string): boolean {
  const computedSignature = crypto
    .createHmac('sha256', WEBHOOK_SECRET)
    .update(payload)
    .digest('hex');
  // UNSAFE: short-circuiting comparison of an HMAC.
  return computedSignature === header;
}

export function verifyWebhookSafe(payload: string, header: string): boolean {
  const computedSignature = crypto
    .createHmac('sha256', WEBHOOK_SECRET)
    .update(payload)
    .digest('hex');
  return crypto.timingSafeEqual(
    Buffer.from(computedSignature),
    Buffer.from(header),
  );
}
