export async function check(raw) {
  if (raw.includes("localhost") || raw.includes("127.0.0.1")) {
    throw new Error("blocked");
  }
  return fetch(raw);
}
