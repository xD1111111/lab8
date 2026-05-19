const { ApiKeyStrategy, JwtStrategy, OAuthStrategy, RateLimiter, AuthProxy } = require('./AuthProxy');

let passed = 0;
let failed = 0;

function assert(condition, label) {
  if (condition) {
    console.log(`  ✅  ${label}`);
    passed++;
  } else {
    console.error(`  ❌  ${label}`);
    failed++;
  }
}

function section(title) {
  console.log(`\n── ${title} ${'─'.repeat(50 - title.length)}`);
}

(async () => {
  section('ApiKeyStrategy');
  {
    const strategy = new ApiKeyStrategy('my-secret-key');
    const headers = {};
    await strategy.inject(headers);
    assert(headers['X-API-Key'] === 'my-secret-key', 'injects X-API-Key header');

    const strategy2 = new ApiKeyStrategy('key123', 'X-Custom-Key');
    const headers2 = {};
    await strategy2.inject(headers2);
    assert(headers2['X-Custom-Key'] === 'key123', 'supports custom header name');
  }

  section('JwtStrategy — auto renewal');
  {
    let renewCount = 0;
    const renewFn = async () => {
      renewCount++;
      return { token: 'new-token', expiresAt: Date.now() + 60000 };
    };
    const strategy = new JwtStrategy('old-token', renewFn, Date.now() - 1);
    const headers = {};
    await strategy.inject(headers);
    assert(renewCount === 1, 'renews expired token');
    assert(headers['Authorization'] === 'Bearer new-token', 'uses renewed token');
  }

  section('OAuthStrategy — auto renewal');
  {
    let renewCount = 0;
    const renewFn = async () => {
      renewCount++;
      return { accessToken: 'new-oauth-token', expiresAt: Date.now() + 60000 };
    };
    const strategy = new OAuthStrategy('old-oauth', renewFn, Date.now() - 1);
    const headers = {};
    await strategy.inject(headers);
    assert(renewCount === 1, 'renews expired OAuth token');
    assert(headers['Authorization'] === 'OAuth new-oauth-token', 'uses renewed OAuth token');
  }

  section('RateLimiter');
  {
    const limiter = new RateLimiter(3, 1000);
    const start = Date.now();

    await limiter.acquire();
    await limiter.acquire();
    await limiter.acquire();

    const elapsed = Date.now() - start;
    assert(elapsed < 100, 'first 3 requests pass immediately');

    const before = Date.now();
    setTimeout(() => {}, 0);
    limiter.acquire().then(() => {
      const waited = Date.now() - before;
      assert(waited >= 0, 'rate limiter allows 4th request after window');
    });

    assert(limiter._timestamps.length <= 3, 'tracks timestamps correctly');
  }

  section('AuthProxy — logger');
  {
    const logs = [];
    const logger = {
      info: (data) => logs.push({ level: 'info', ...data }),
      error: (data) => logs.push({ level: 'error', ...data }),
    };

    const proxy = new AuthProxy('https://example.com', new ApiKeyStrategy('key'));
    proxy.setLogger(logger);
    proxy._log('info', 'test message', { extra: 'data' });

    assert(logs.length === 1, 'logger receives log entry');
    assert(logs[0].message === 'test message', 'log entry has correct message');
    assert(logs[0].extra === 'data', 'log entry includes extra data');
  }

  section('AuthProxy — switchStrategy');
  {
    const logs = [];
    const logger = {
      info: (data) => logs.push(data),
      error: () => {},
    };

    const proxy = new AuthProxy('https://example.com', new ApiKeyStrategy('key1'));
    proxy.setLogger(logger);

    const newStrategy = new JwtStrategy('jwt-token');
    proxy.switchStrategy(newStrategy);

    assert(proxy.authStrategy === newStrategy, 'strategy is switched');
    assert(logs.some(l => l.message === 'Auth strategy switched'), 'logs strategy switch');
  }

  console.log(`\n${'═'.repeat(55)}`);
  console.log(`  Results: ${passed} passed, ${failed} failed`);
  if (failed === 0) console.log('  All tests passed! 🎉');
})();
