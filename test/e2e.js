'use strict'
'use strict'

const test = require('node:test')
const assert = require('node:assert')

const fastify = require('fastify')
const mtlsPlugin = require('..')
const { MockAgent, setGlobalDispatcher, request } = require('undici')
const UndiciTLSDispatcher = require('undici-tls-dispatcher')
const generateCertificates = require('./fixtures/generate')

const certificates = generateCertificates(['client.local', 'server.local'])

test('should implement mTLS', async (t) => {
  const { url, server } = await buildServer()
  const key = certificates['client.local'].privateKey
  const ca = certificates.CA
  const cert = certificates['client.local'].certificate
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
  const serverPort = server.addresses()[0].port
  const res = await request(`https://localhost:${serverPort}/mtls`, { dispatcher })
  const body = await res.body.json()
  assert.strictEqual(body.message, 'You are client.local')

  // // should not connect without certificate
  // try {
  //   const dispatcher = new UndiciTLSDispatcher({
  //     tlsConfig: [
  //       { url, tls: { ca } }
  //     ]
  //   })
  //   await request(`https://localhost:${serverPort}/mtls`, { dispatcher })
  // } catch (err) {
  //   assert.strictEqual(err.code, 'UND_ERR_SOCKET')
  //   assert.strictEqual(err.message, 'other side closed')
  // }

  // // Should give self-signed error if CA chain is not configured in the client
  // try {
  //   await request(`https://localhost:${serverPort}/mtls`)
  // } catch (err) {
  //   assert.strictEqual(err.code, 'SELF_SIGNED_CERT_IN_CHAIN')
  //   assert.strictEqual(err.message, 'self-signed certificate in certificate chain')
  // }

  await server.close()
})

async function buildServer () {
  const key = certificates['server.local'].privateKey
  const ca = certificates.CA
  const cert = certificates['server.local'].certificate
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
  const url = await server.listen({ host: 'localhost', port: 0 })
  return { url, server }
}
