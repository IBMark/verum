// Service configuration. The live-mode key literal below is the classic
// copy-pasted-config leak shape; the env read underneath is the safe idiom.
import Stripe from 'stripe';

export const stripe = new Stripe('sk_live_9aB3cD4eF5gH6iJ7');

export const stripeFromEnv = new Stripe(process.env.STRIPE_SECRET_KEY ?? '');

export const config = {
  currency: 'usd',
  apiVersion: '2024-06-20',
};
