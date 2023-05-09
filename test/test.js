'use strict'

const test = require('node:test')
const assert = require('node:assert')
const { readFile } = require('node:fs/promises')
const { join } = require('node:path')

const fastify = require('fastify')
const mtlsPlugin = require('..')
const { MockAgent, setGlobalDispatcher } = require('undici')
const fixturesDirectory = join(__dirname, 'fixtures')

test('should decorate server with tls data', async (t) => {
  const key = await readFile(join(fixturesDirectory, 'key.pem'), 'utf-8')
  const ca = await readFile(join(fixturesDirectory, 'ca.pem'), 'utf-8')
  const cert = await readFile(join(fixturesDirectory, 'cert.pem'), 'utf-8')
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
    commonName: 'example.com',
    ttl: '365d'
  }
  const server = fastify({
    https: {
      key: '',
      cert: ''
    }
  })

  server.register(mtlsPlugin, mtlsOptions)
  const url = await server.listen({ port: 0 })
  assert.match(url, /^https:\/\//)
  assert.deepEqual(server.mtls, { ca, cert, key })
  await server.close()
})
