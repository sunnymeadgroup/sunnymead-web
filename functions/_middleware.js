// Render current package prices before the homepage reaches the browser.
import { DEFAULT_PRICING, validPricing } from "./api/[[path]].js";

export async function onRequest(context) {
  const pathname = new URL(context.request.url).pathname;
  if (!["/", "/index.html"].includes(pathname) || context.request.method !== "GET") return context.next();

  let prices = null;
  try {
    if (context.env.DB) {
      const stored = await context.env.DB.get("website_pricing", "json");
      prices = stored === null ? DEFAULT_PRICING : validPricing(stored);
    }
  } catch { /* Show an enquiry prompt rather than stale prices. */ }

  const response = await context.next();
  if (!response.ok || !(response.headers.get("content-type") || "").includes("text/html")) return response;
  const headers = new Headers(response.headers);
  headers.set("cache-control", "no-store");
  headers.delete("content-length");
  headers.delete("etag");
  let rewriter = new HTMLRewriter();
  const money = value => "£" + value.toLocaleString("en-GB", { minimumFractionDigits: value % 1 ? 2 : 0, maximumFractionDigits: 2 });
  for (const id of Object.keys(DEFAULT_PRICING)) {
    const selector = '[data-price-plan="' + id + '"]';
    if (prices) {
      const plan = prices[id], pennies = Math.round(plan.setup * 100), first = Math.floor(pennies / 2);
      rewriter = rewriter
        .on(selector + ' [data-price="setup"]', { element(el) { el.setInnerContent(money(plan.setup)); } })
        .on(selector + ' [data-price="monthly"]', { element(el) { el.setInnerContent(money(plan.monthly)); } })
        .on(selector + ' .pay', { element(el) { el.setInnerContent(money(first / 100) + " to start, " + money((pennies - first) / 100) + " when you're happy."); } });
    } else {
      rewriter = rewriter
        .on(selector + ' [data-price="setup"]', { element(el) { el.setInnerContent("Please enquire"); } })
        .on(selector + ' .price small', { element(el) { el.setAttribute("hidden", ""); } })
        .on(selector + ' .monthly', { element(el) { el.setAttribute("hidden", ""); } })
        .on(selector + ' .pay', { element(el) { el.setAttribute("hidden", ""); } });
    }
  }
  return rewriter.transform(new Response(response.body, { status: response.status, statusText: response.statusText, headers }));
}
