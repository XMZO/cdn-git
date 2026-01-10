
const express = require('express');
const fetch = require('node-fetch');
const Redis = require('ioredis');

const app = express();
const compression = require('compression');
app.use(compression());

const ASSET_URL = 'https://cdn.jsdelivr.net';
const ALLOWED_GH_USERS = ['XMZO', 'starsei'];
const DEFAULT_GH_USER = 'XMZO';

// ���� Redis
const redis = new Redis({
  host: process.env.REDIS_HOST || '127.0.0.1',
  port: parseInt(process.env.REDIS_PORT) || 6379,
  maxRetriesPerRequest: 3,
  lazyConnect: true
});

redis.on('error', (err) => console.error('Redis error:', err));
redis.on('connect', () => console.log('Redis connected'));

// ����ʱ�����ã��룩
const CACHE_CONFIG = {
  'js': 2592000, 'css': 2592000, 'png': 2592000, 'jpg': 2592000,
  'jpeg': 2592000, 'gif': 2592000, 'svg': 2592000, 'ico': 2592000,
  'woff': 2592000, 'woff2': 2592000, 'ttf': 2592000, 'eot': 2592000,
  'webp': 2592000, 'moc3': 2592000, 'map': 2592000, 'cur': 2592000,
  'mp4': 604800, 'mp3': 604800, 'pdf': 604800,
  'json': 86400, 'xml': 86400, 'txt': 86400, 
  'html': 3600, 'default': 86400
};

// �����ļ���չ����ȡ����ʱ��
function getCacheTTL(filePath) {
  const match = filePath.match(/\.([^./?#]+)(?:[?#]|$)/);
  const ext = match ? match[1].toLowerCase() : null;
  return CACHE_CONFIG[ext] || CACHE_CONFIG['default'];
}

// ����ָ���û�������
app.get(/^\/gh\/([^\/]+)\/(.+)$/, async (req, res) => {
  const ghUser = req.params[0];
  const filePath = req.params[1];

  if (!ALLOWED_GH_USERS.some(u => u.toLowerCase() === ghUser.toLowerCase())) {
    return res.status(403).send(`Access denied: User "${ghUser}" is not authorized`);
  }

  await fetchWithCache(`${ASSET_URL}/gh/${ghUser}/${filePath}`, req.path, res);
});

// ����Ĭ���û�������
app.get(/^\/(.*)$/, async (req, res) => {
  const reqPath = req.params[0];
  if (reqPath === 'works') return res.send('it works');
  await fetchWithCache(`${ASSET_URL}/gh/${DEFAULT_GH_USER}/${reqPath}`, req.path, res);
});

async function fetchWithCache(cdnUrl, reqPath, res) {
  try {
    // �� Redis ��ȡ����
    const cached = await redis.getBuffer(cdnUrl);
    const cachedType = await redis.get(`${cdnUrl}:type`);
  
    if (cached && cachedType) {
      res.set('X-Proxy-Cache', 'HIT');
      res.set('Content-Type', cachedType);
      return res.send(cached);
    }
  
    // ����δ���У��� CDN ��ȡ
    const response = await fetch(cdnUrl);
    if (!response.ok) {
      res.set('X-Proxy-Cache', 'BYPASS');
      return res.status(response.status).send(await response.text());
    }
  
    const body = await response.buffer();
    const ct = response.headers.get('content-type') || 'application/octet-stream';
    const ttl = getCacheTTL(reqPath);
  
    // �첽д�� Redis����������Ӧ��
    redis.setex(cdnUrl, ttl, body).catch(e => console.error('Cache write error:', e));
    redis.setex(`${cdnUrl}:type`, ttl, ct).catch(e => console.error('Cache meta error:', e));
  
    res.set({
      'X-Proxy-Cache': 'MISS',
      'Cache-Control': `public, max-age=${ttl}`,
      'Content-Type': ct
    });
    res.send(body);
  } catch (error) {
    res.status(502).send('Fetch error: ' + error.message);
  }
}

// ����������
redis.connect().then(() => {
  app.listen(process.env.PORT || 3000, '0.0.0.0', () => console.log('Server running on port 3000'));
});


