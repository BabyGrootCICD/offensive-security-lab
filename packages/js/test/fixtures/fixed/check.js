export async function check() {
  return fetch("https://inventory.internal/stock");
}
