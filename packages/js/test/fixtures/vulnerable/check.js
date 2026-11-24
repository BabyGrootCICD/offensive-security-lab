export async function check(req) {
  const stockApi = req.query.stockApi;
  return fetch(stockApi);
}
