const f = <T,>(x: T): T => x;
const g = <T extends object>(x: T) => <div>{String(x)}</div>;
