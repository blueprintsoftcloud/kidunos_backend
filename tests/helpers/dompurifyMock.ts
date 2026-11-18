// Lightweight Jest stub for isomorphic-dompurify so Jest CJS test loading of server.ts
// does not pull jsdom's ESM transitive dependency tree (@exodus/bytes, @csstools/*.mjs).
const dompurifyStub = {
  sanitize: (input: string) => input,
};

export default dompurifyStub;

