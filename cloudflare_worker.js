/**
 * Milijon - Cloudflare Worker WebSocket Proxy Relay
 * 
 * استفاده از این ورکر به شما امکان می‌دهد تمام آی‌پی‌های تمیز کلادفلر (Clean IPs)
 * را با دامنه ریلوی بدون قطعی استفاده نمایید.
 * 
 * راهنما:
 * ۱. یک Worker در حساب کلادفلر ایجاد کرده و این کد را در آن قرار دهید.
 * ۲. متغیر BACKEND_DOMAIN را با دامنه ریلوی خود (بدون https://) جایگزین کنید.
 */

const BACKEND_DOMAIN = "YOUR_APP.up.railway.app";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const upgradeHeader = request.headers.get("Upgrade");

    // اگر درخواست WebSocket باشد (ترافیک پروکسی VLESS / Trojan)
    if (upgradeHeader && upgradeHeader.toLowerCase() === "websocket") {
      url.hostname = env.BACKEND_DOMAIN || BACKEND_DOMAIN;
      const newRequest = new Request(url, {
        method: request.method,
        headers: request.headers,
        body: request.body,
        redirect: "manual"
      });
      return fetch(newRequest);
    }

    // هدایت درخواست‌های وب به داشبورد اصلی
    url.hostname = env.BACKEND_DOMAIN || BACKEND_DOMAIN;
    return fetch(new Request(url, request));
  }
};
