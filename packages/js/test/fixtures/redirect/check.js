export async function check(raw) {
  return fetch(raw, { redirect: "follow" });
}
