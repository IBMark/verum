import { render } from './ui.js';

export class Widget {
  constructor(name) { this.name = name; }
  draw() { return render(this.name); }
}

export const make = (n) => new Widget(n);

async function boot() { const r = await fetch('/api/v1/items'); return r.json(); }
boot();
