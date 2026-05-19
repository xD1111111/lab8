const https = require('https');
const http = require('http');

class ApiKeyStrategy {
  constructor(apiKey, headerName = 'X-API-Key') {
    this.apiKey = apiKey;
    this.headerName = headerName;
  }

  async inject(headers) {
    headers[this.headerName] = this.apiKey;
  }
}

class JwtStrategy {
  constructor(token, renewFn = null, expiresAt = null) {
    this.token = token;
    this.renewFn = renewFn;
    this.expiresAt = expiresAt;
  }

  async inject(headers) {
    if (this.renewFn && this.expiresAt && Date.now() >= this.expiresAt) {
      const renewed = await this.renewFn();
      this.token = renewed.token;
      this.expiresAt = renewed.expiresAt;
    }
    headers['Authorization'] = `Bearer ${this.token}`;
  }
}

class OAuthStrategy {
  constructor(accessToken, renewFn = null, expiresAt = null) {
    this.accessToken = accessToken;
    this.renewFn = renewFn;
    this.expiresAt = expiresAt;
  }

  async inject(headers) {
    if (this.renewFn && this.expiresAt && Date.now() >= this.expiresAt) {
      const renewed = await this.renewFn();
      this.accessToken = renewed.accessToken;
      this.expiresAt = renewed.expiresAt;
    }
    headers['Authorization'] = `OAuth ${this.accessToken}`;
  }
}

class RateLimiter {
  constructor(maxRequests, windowMs) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
    this._timestamps = [];
  }

  async acquire() {
    const now = Date.now();
    this._timestamps = this._timestamps.filter(t => now - t < this.windowMs);

    if (this._timestamps.length >= this.maxRequests) {
      const oldest = this._timestamps[0];
      const waitMs = this.windowMs - (now - oldest);
      await new Promise((resolve) => setTimeout(resolve, waitMs));
      return this.acquire();
    }

    this._timestamps.push(Date.now());
  }
}

class AuthProxy {
  constructor(baseUrl, authStrategy, options = {}) {
    this.baseUrl = baseUrl;
    this.authStrategy = authStrategy;
    this._logger = null;
    this._rateLimiter = options.rateLimiter || null;
  }

  setLogger(logger) {
    this._logger = logger;
  }

  _log(level, message, data = {}) {
    if (this._logger) {
      this._logger[level]({ message, ...data });
    }
  }

  async request(method, path, options = {}) {
    if (this._rateLimiter) {
      await this._rateLimiter.acquire();
    }

    const headers = { ...(options.headers || {}) };
    await this.authStrategy.inject(headers);

    const url = new URL(path, this.baseUrl);
    const isHttps = url.protocol === 'https:';
    const lib = isHttps ? https : http;

    const reqOptions = {
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: url.pathname + url.search,
      method,
      headers,
    };

    this._log('info', 'Outgoing request', { method, url: url.href });

    return new Promise((resolve, reject) => {
      const req = lib.request(reqOptions, (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          this._log('info', 'Response received', { status: res.statusCode });
          resolve({ status: res.statusCode, headers: res.headers, body });
        });
      });

      req.on('error', (err) => {
        this._log('error', 'Request failed', { error: err.message });
        reject(err);
      });

      if (options.body) req.write(options.body);
      req.end();
    });
  }

  switchStrategy(newStrategy) {
    this.authStrategy = newStrategy;
    this._log('info', 'Auth strategy switched', { strategy: newStrategy.constructor.name });
  }

  get(path, options = {})    { return this.request('GET', path, options); }
  post(path, options = {})   { return this.request('POST', path, options); }
  put(path, options = {})    { return this.request('PUT', path, options); }
  delete(path, options = {}) { return this.request('DELETE', path, options); }
}

module.exports = { AuthProxy, ApiKeyStrategy, JwtStrategy, OAuthStrategy, RateLimiter };
