export const App = ({ title }: { title: string }) => (
  <div className="app"><h1>{title}</h1>{[1, 2].map(n => <span key={n}>{n}</span>)}</div>
);
