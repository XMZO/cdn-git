import http from 'http';
import https from 'https';

// ===== 配置 =====
const PORT = process.env.PORT || 3000;
const DEFAULT_TARGET = process.env.DEFAULT_TARGET || '';
const WORKER_SECRET_KEY = process.env.WORKER_SECRET_KEY || '';

// HOST_MAPPING: JSON 格式，如 {"umi.li":"cloudflare-imgbed-buu.pages.dev"}
const HOST_MAPPING = process.env.HOST_MAPPING
    ? JSON.parse(process.env.HOST_MAPPING)
    : {};

const STATIC_EXTS = new Set([
    'png', 'jpg', 'jpeg', 'webp', 'avif', 'gif', 'svg', 'ico', 'bmp', 'heic', 'heif',
    'css', 'js', 'ttf', 'otf', 'woff', 'woff2', 'pdf', 'mp4', 'webm'
]);

// ===== 工具函数 =====
function isStaticPath(pathname) {
    if (pathname.startsWith('/file/') || pathname.startsWith('/img/')) {
        return true;
    }
    const parts = pathname.split('.');
    if (parts.length < 2) return false;
    const ext = parts.pop().toLowerCase();
    return STATIC_EXTS.has(ext);
}

function rewriteBody(body, reqOrigin) {
    // 替换 pages.dev 域名
    const pagesDevPattern = /https?:\/\/[^/"'\s]*\.pages\.dev/gi;
    // 替换 hf.space 域名
    const hfSpacePattern = /https?:\/\/[^/"'\s]*\.hf\.space/gi;

    return body
        .replace(pagesDevPattern, reqOrigin)
        .replace(hfSpacePattern, reqOrigin);
}

// ===== 代理请求 =====
async function proxyRequest(req, res) {
    const reqHost = req.headers.host?.split(':')[0] || 'localhost';
    const targetHost = HOST_MAPPING[reqHost] || DEFAULT_TARGET;

    const targetUrl = new URL(req.url, `https://${targetHost}`);
    const reqOrigin = `${req.headers['x-forwarded-proto'] || 'http'}://${req.headers.host}`;

    // 复制请求头，修改 Host
    const headers = { ...req.headers };
    headers.host = targetHost;
    delete headers['connection'];
    delete headers['keep-alive'];
    // 禁用压缩，避免处理 gzip 响应
    delete headers['accept-encoding'];

    // 添加验证头
    if (WORKER_SECRET_KEY) {
        headers['x-forwarded-by-worker'] = WORKER_SECRET_KEY;
    }

    const options = {
        hostname: targetHost,
        port: 443,
        path: targetUrl.pathname + targetUrl.search,
        method: req.method,
        headers: headers,
    };

    return new Promise((resolve) => {
        const proxyReq = https.request(options, (proxyRes) => {
            const contentType = proxyRes.headers['content-type'] || '';

            // 处理重定向 - 重写 Location
            if (proxyRes.statusCode >= 300 && proxyRes.statusCode < 400) {
                const location = proxyRes.headers['location'];
                if (location) {
                    proxyRes.headers['location'] = rewriteBody(location, reqOrigin);
                }
                res.writeHead(proxyRes.statusCode, proxyRes.headers);
                res.end();
                return resolve();
            }

            // 处理 JSON 响应 - 重写域名
            if (contentType.includes('application/json')) {
                let body = '';
                proxyRes.on('data', chunk => body += chunk);
                proxyRes.on('end', () => {
                    const rewritten = rewriteBody(body, reqOrigin);
                    const newHeaders = { ...proxyRes.headers };
                    delete newHeaders['content-length'];
                    delete newHeaders['transfer-encoding'];
                    newHeaders['content-length'] = Buffer.byteLength(rewritten);
                    res.writeHead(proxyRes.statusCode, newHeaders);
                    res.end(rewritten);
                    resolve();
                });
                return;
            }

            // 处理 HTML 响应 - 重写域名（用于登录页面等）
            if (contentType.includes('text/html')) {
                let body = '';
                proxyRes.on('data', chunk => body += chunk);
                proxyRes.on('end', () => {
                    const rewritten = rewriteBody(body, reqOrigin);
                    const newHeaders = { ...proxyRes.headers };
                    delete newHeaders['content-length'];
                    delete newHeaders['transfer-encoding'];
                    newHeaders['content-length'] = Buffer.byteLength(rewritten);
                    res.writeHead(proxyRes.statusCode, newHeaders);
                    res.end(rewritten);
                    resolve();
                });
                return;
            }

            // 其他响应直接转发
            res.writeHead(proxyRes.statusCode, proxyRes.headers);
            proxyRes.pipe(res);
            proxyRes.on('end', resolve);
        });

        proxyReq.on('error', (err) => {
            console.error('Proxy error:', err.message);
            res.writeHead(502, { 'Content-Type': 'text/plain' });
            res.end('Bad Gateway');
            resolve();
        });

        // 转发请求体
        req.pipe(proxyReq);
    });
}

// ===== 启动服务器 =====
const server = http.createServer(proxyRequest);

server.listen(PORT, () => {
    console.log(`🚀 Reverse proxy running on http://0.0.0.0:${PORT}`);
    console.log(`📍 Default target: ${DEFAULT_TARGET}`);
});
