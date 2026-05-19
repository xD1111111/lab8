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
  constructor(token) {
    this.token = token;
  }

  async inject(headers) {
    headers['Authorization'] = `Bearer ${this.token}`;
  }
}

class OAuthStrategy {
  constructor(accessToken) {
    this.accessToken = accessToken;
  }

  async inject(headers) {
    headers['Authorization'] = `OAuth ${this.accessToken}`;
  }
}

class AuthProxy {
  constructor(baseUrl, authStrategy) {
    this.baseUrl = baseUrl;
    this.authStrategy = authStrategy;
    this._logger = null;
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

  get(path, options = {})    { return this.request('GET', path, options); }
  post(path, options = {})   { return this.request('POST', path, options); }
  put(path, options = {})    { return this.request('PUT', path, options); }
  delete(path, options = {}) { return this.request('DELETE', path, options); }
}

module.exports = { AuthProxy, ApiKeyStrategy, JwtStrategy, OAuthStrategy };
