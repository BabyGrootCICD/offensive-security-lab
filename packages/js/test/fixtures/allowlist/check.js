export async function check(raw) {
  const parsed = new URL(raw);
  if (parsed.protocol !== "https:" || parsed.hostname !== "inventory.internal") {
    throw new Error("destination not allowed");
  }
  return fetch(parsed.toString());
}
