'use strict'
'use strict'

const test = require('node:test')
const assert = require('node:assert')
const { readFile } = require('node:fs/promises')
const { join } = require('node:path')

const fastify = require('fastify')
const mtlsPlugin = require('..')
const { MockAgent, setGlobalDispatcher, request } = require('undici')
const UndiciTLSDispatcher = require('undici-tls-dispatcher')

const fixturesDirectory = join(__dirname, 'fixtures', 'e2e')

test('should implement mTLS', async (t) => {
  const { url, server } = await buildServer()
  const key = await readFile(join(fixturesDirectory, 'client', 'key.pem'), 'utf-8')
  const ca = await readFile(join(fixturesDirectory, 'client', 'ca.pem'), 'utf-8')
  const cert = await readFile(join(fixturesDirectory, 'client', 'cert.pem'), 'utf-8')
  const dispatcher = new UndiciTLSDispatcher({
    tlsConfig: [
      {
        url,
        tls: {
          ca,
          cert,
          key
        }
      }
    ]
  })
  const res = await request(`${url}/mtls`, { dispatcher })
  const body = await res.body.json()
  assert.strictEqual(body.message, 'You are client.test.fly.dev') // fixtures certificate is valid for this host

  // should not connect without certificate
  try {
    const dispatcher = new UndiciTLSDispatcher({
      tlsConfig: [
        { url, tls: { ca } }
      ]
    })
    await request(`${url}/mtls`, { dispatcher })
  } catch (err) {
    assert.strictEqual(err.code, 'UND_ERR_SOCKET')
    assert.strictEqual(err.message, 'other side closed')
  }

  // Should give self-signed error if CA chain is not configured in the client
  try {
    await request(`${url}/mtls`)
  } catch (err) {
    assert.strictEqual(err.code, 'SELF_SIGNED_CERT_IN_CHAIN')
    assert.strictEqual(err.message, 'self-signed certificate in certificate chain')
  }

  await server.close()
})

async function buildServer () {
  const key = await readFile(join(fixturesDirectory, 'server', 'key.pem'), 'utf-8')
  const ca = await readFile(join(fixturesDirectory, 'server', 'ca.pem'), 'utf-8')
  const cert = await readFile(join(fixturesDirectory, 'server', 'cert.pem'), 'utf-8')
  const mockAgent = new MockAgent()
  mockAgent
    .get('http://vault.cluster')
    .intercept({
      method: 'POST',
      path: '/v1/auth/approle/login'
    })
    .reply(200, { auth: { client_token: 'a-sample-token' } })
  mockAgent
    .get('http://vault.cluster')
    .intercept({
      method: 'POST',
      path: '/v1/your_ca/issue/ca_role'
    })
    .reply(200, {
      data: {
        private_key: key,
        ca_chain: ca,
        certificate: cert
      }
    })

  setGlobalDispatcher(mockAgent)
  const mtlsOptions = {
    vaultNamespace: 'admin',
    vaultAddress: 'http://vault.cluster',
    roleId: 'fake-role-id',
    secretId: 'fake-secret-id',
    CAName: 'your_ca',
    PKIRole: 'ca_role',
    commonName: 'server.test.fly.dev',
    ttl: '18000h'
  }
  const server = fastify({
    https: {
      key: '',
      cert: '',
      requestCert: true,
      rejectUnauthorized: true
    }
  })

  server.register(mtlsPlugin, mtlsOptions)
  server.get('/mtls', async (req, res) => {
    const clientcert = req.raw.socket.getPeerCertificate(false)
    return { message: `You are ${clientcert.subject.CN}` }
  })
  const url = await server.listen({ host: '0.0.0.0', port: 0 })
  return { url, server }
}
