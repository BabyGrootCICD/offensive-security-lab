export async function check(raw) {
  const parsed = new URL(raw);
  if (!parsed.hostname.includes("trusted.example")) {
    throw new Error("host not allowed");
  }
  return fetch(parsed.toString());
}
