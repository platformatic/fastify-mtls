const fp = require('fastify-plugin')
const getCertificate = require('vault-pki-fetcher')

async function fastifyMTLS (app, options) {
  const tls = await getCertificate(options)
  const { key, cert, ca } = tls
  app.decorate('mtls', {
    key, cert, ca
  })
  app.server.setSecureContext({
    key,
    cert,
    ca
  })
}

module.exports = fp(fastifyMTLS, {
  fastify: '4.x',
  name: 'fastify-mtls'
})

module.exports.default = fastifyMTLS
module.exports.fastifyMTLS = fastifyMTLS
