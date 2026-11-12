

const ALLOWED_ORIGINS = [
  "https://myridebhilwara-45652.web.app",
  "https://myridebhilwara-45652.firebaseapp.com",
  "https://ultrahdvivox-spec.github.io"
];

function response(data, status = 200, origin = "") {
  const headers = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization"
  };

  if (ALLOWED_ORIGINS.includes(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Vary"] = "Origin";
  }

  return new Response(JSON.stringify(data), {
    status,
    headers
  });
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";

    if (request.method === "OPTIONS") {
      if (!ALLOWED_ORIGINS.includes(origin)) {
        return new Response(null, { status: 403 });
      }

      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
          "Access-Control-Max-Age": "86400",
          "Vary": "Origin"
        }
      });
    }

    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return response({
        success: true,
        service: "WHERE IS MY RIDE OTP",
        status: "ready",
        version: "1.0.0",
        otpEnabled: false
      }, 200, origin);
    }

    if (request.method === "POST" &&
        (url.pathname === "/otp/send" ||
         url.pathname === "/otp/verify")) {
      return response({
        success: false,
        message: "OTP service is not configured yet.",
        otpEnabled: false
      }, 503, origin);
    }

    return response({
      success: false,
      message: "Endpoint not found"
    }, 404, origin);
  }
};
