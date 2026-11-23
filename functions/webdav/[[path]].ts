import { notFound, parseBucketPath } from "./utils";
import { handleRequestCopy } from "./copy";
import { handleRequestDelete } from "./delete";
import { handleRequestGet } from "./get";
import { handleRequestHead } from "./head";
import { handleRequestMkcol } from "./mkcol";
import { handleRequestMove } from "./move";
import { handleRequestPropfind } from "./propfind";
import { handleRequestPut } from "./put";
import { handleRequestPost } from "./post";
import { RequestHandlerParams } from "./utils";

const ALLOW_ORIGIN = "https://cent.112133.xyz"; // ✅ 不带 ?、不带 /

const ALLOWED_METHODS = [
  "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS",
  "PROPFIND", "MKCOL", "COPY", "MOVE",
] as const;

const ALLOWED_HEADERS = [
  "Authorization", "Content-Type", "Depth",
  "If-Match", "If-None-Match", "X-Requested-With",
  "Destination", "Overwrite",
].join(", ");

function withCORS(response: Response): Response {
  const headers = new Headers(response.headers);
  headers.set("Access-Control-Allow-Origin", ALLOW_ORIGIN);
  headers.set("Access-Control-Allow-Methods", ALLOWED_METHODS.join(", "));
  headers.set("Access-Control-Allow-Headers", ALLOWED_HEADERS);
  headers.set("Access-Control-Max-Age", "86400");
  // 若以后需要前端读取 Authorization 等响应头，再按需加；
  // 不要图省事直接设 "*"，尤其在带凭证的场景。
  headers.set("Vary", "Origin");

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function corsPreflight(): Response {
  return withCORS(new Response(null, { status: 204 }));
}

function methodNotAllowed(): Response {
  return withCORS(new Response("Method Not Allowed", {
    status: 405,
    headers: { Allow: ALLOWED_METHODS.join(", ") },
  }));
}

const HANDLERS: Record<
  string,
  (context: RequestHandlerParams) => Promise<Response>
> = {
  PROPFIND: handleRequestPropfind,
  MKCOL: handleRequestMkcol,
  HEAD: handleRequestHead,
  GET: handleRequestGet,
  POST: handleRequestPost,
  PUT: handleRequestPut,
  COPY: handleRequestCopy,
  MOVE: handleRequestMove,
  DELETE: handleRequestDelete,
};

export const onRequest: PagesFunction = async (context) => {
  let request = context.request;
  const url = new URL(request.url);

  // 浏览器真实发出的 OPTIONS 预检，必须在重写方法前处理。
  // 不能用 ?method=OPTIONS 绕过后面的鉴权。
  if (request.method === "OPTIONS" && !url.searchParams.has("method")) {
    return corsPreflight();
  }

  // Cent 的浏览器兼容模式：POST /path?method=PROPFIND => PROPFIND /path
  const override = url.searchParams.get("method");
  if (override) {
    const realMethod = override.toUpperCase();

    if (!ALLOWED_METHODS.includes(realMethod as any)) {
      return withCORS(new Response(`Unsupported method override: ${override}`, {
        status: 400,
      }));
    }

    // OPTIONS 不适合作为业务方法覆盖，避免形成匿名能力探测口。
    if (realMethod === "OPTIONS") {
      return withCORS(new Response("OPTIONS override is not allowed", {
        status: 400,
      }));
    }

    url.searchParams.delete("method");

    // ✅ 关键修复：GET/HEAD 没有请求体，不能照搬原 body。
    const hasBody = !["GET", "HEAD"].includes(realMethod);
    request = new Request(url.toString(), {
      method: realMethod,
      headers: request.headers,
      body: hasBody ? request.body : undefined,
      // 必须保留，否则流式请求体在部分 Cloudflare 路由下会报错。
      duplex: hasBody ? "half" : undefined,
      redirect: "manual",
    } as RequestInit);
  }

  const isPublicRead =
    env.WEBDAV_PUBLIC_READ === "1" &&
    ["GET", "HEAD", "PROPFIND"].includes(request.method);

  if (!isPublicRead) {
    if (!env.WEBDAV_USERNAME || !env.WEBDAV_PASSWORD) {
      return withCORS(new Response("WebDAV protocol is not enabled", {
        status: 403,
      }));
    }

    const auth = request.headers.get("Authorization");
    const expected = `Basic ${btoa(`${env.WEBDAV_USERNAME}:${env.WEBDAV_PASSWORD}`)}`;

    // 时序安全比较，避免逐字符泄露差异
    const same = auth?.length === expected.length &&
      auth.split("").reduce((acc, ch, i) => acc | (ch.charCodeAt(0) ^ expected.charCodeAt(0)), 0) === 0;

    if (!same) {
      return withCORS(new Response("Unauthorized", {
        status: 401,
        headers: { "WWW-Authenticate": 'Basic realm="WebDAV"' },
      }));
    }
  }

  const [bucket, path] = parseBucketPath(context);
  if (!bucket) return withCORS(notFound());

  const handler = HANDLERS[request.method] ?? methodNotAllowed;

  // ✅ 关键修复：传 request，不要传 context.request
  return withCORS(await handler({ bucket, path, request }));
};
