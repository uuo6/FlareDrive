import { notFound, parseBucketPath } from "./utils";
import { handleRequestCopy } from "./copy";
import { handleRequestDelete } from "./delete";
import { handleRequestGet } from "./get";
import { handleRequestHead } from "./head";
import { handleRequestMkcol } from "./mkcol";
import { handleRequestMove } from "./move";
import { handleRequestPropfind } from "./propfind";
import { handleRequestPut } from "./put";
import { RequestHandlerParams } from "./utils";
import { handleRequestPost } from "./post";

// 👇 这是新增的 CORS 处理函数
function withCORS(response: Response): Response {
  const newResponse = new Response(response.body, response);
  // 请确保下面的网址是你的 Cent 域名，千万不要带末尾的斜杠 /
  newResponse.headers.set("Access-Control-Allow-Origin", "https://cent.112133.xyz?method="); 
  newResponse.headers.set("Access-Control-Allow-Methods", "GET, HEAD, POST, PUT, DELETE, OPTIONS, PROPFIND, MKCOL, COPY, MOVE");
  newResponse.headers.set("Access-Control-Allow-Headers", "Authorization, Content-Type, Depth, If-Match, If-None-Match, X-Requested-With, Destination, Overwrite");
  newResponse.headers.set("Access-Control-Max-Age", "86400");
  return newResponse;
}

async function handleRequestOptions() {
  return new Response(null, {
    headers: {
      Allow: Object.keys(HANDLERS).join(", "),
      DAV: "1",
    },
  });
}

async function handleMethodNotAllowed() {
  return new Response(null, { status: 405 });
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

  export const onRequest: PagesFunction<...> = async function (context) {
  const env = context.env;
  let request: Request = context.request;
  
  // 👇 新增：如果 URL 里有 method 参数，用它替换请求的真实方法
  const url = new URL(request.url);
  const realMethod = url.searchParams.get("method");
  if (realMethod) {
    request = new Request(request, { method: realMethod });
  }

  // 下面保持你原来的逻辑不变
  if (request.method === "OPTIONS") return withCORS(await handleRequestOptions());

  const skipAuth =
    env.WEBDAV_PUBLIC_READ === "1" &&
    ["GET", "HEAD", "PROPFIND"].includes(request.method);

  if (!skipAuth) {
    // 👇 用 withCORS 包裹 403 响应
    if (!env.WEBDAV_USERNAME || !env.WEBDAV_PASSWORD)
      return withCORS(new Response("WebDAV protocol is not enabled", { status: 403 }));

    const auth = request.headers.get("Authorization");
    // 👇 用 withCORS 包裹 401 响应
    if (!auth) {
      return withCORS(new Response("Unauthorized", {
        status: 401,
        headers: { "WWW-Authenticate": `Basic realm="WebDAV"` },
      }));
    }
    const expectedAuth = `Basic ${btoa(
      `${env.WEBDAV_USERNAME}:${env.WEBDAV_PASSWORD}`
    )}`;
    // 👇 用 withCORS 包裹 401 响应
    if (auth !== expectedAuth)
      return withCORS(new Response("Unauthorized", { status: 401 }));
  }

  const [bucket, path] = parseBucketPath(context);
  if (!bucket) return withCORS(notFound());

  const method: string = (context.request as Request).method;
  const handler = HANDLERS[method] ?? handleMethodNotAllowed;
  
  // 👇 最后，用 withCORS 包裹真正的文件操作响应
  const finalResponse = await handler({ bucket, path, request: context.request });
  return withCORS(finalResponse);
};
