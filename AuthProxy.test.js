const { ApiKeyStrategy, JwtStrategy, OAuthStrategy } = require('./AuthProxy');

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

  section('JwtStrategy');
  {
    const strategy = new JwtStrategy('jwt-token-abc');
    const headers = {};
    await strategy.inject(headers);
    assert(headers['Authorization'] === 'Bearer jwt-token-abc', 'injects Bearer token');
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

  section('OAuthStrategy');
  {
    const strategy = new OAuthStrategy('oauth-token-xyz');
    const headers = {};
    await strategy.inject(headers);
    assert(headers['Authorization'] === 'OAuth oauth-token-xyz', 'injects OAuth token');
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

  console.log(`\n${'═'.repeat(55)}`);
  console.log(`  Results: ${passed} passed, ${failed} failed`);
  if (failed === 0) console.log('  All tests passed! 🎉');
})();
