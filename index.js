const fp = require('fastify-plugin')
const getCertificate = require('vault-pki-fetcher')

async function fastifyMTLS (app, options, done) {
  app.addHook('onReady', async () => {
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
  })
  done()
}

module.exports = fp(fastifyMTLS, {
  fastify: '4.x',
  name: 'fastify-mtls'
})

module.exports.default = fastifyMTLS
module.exports.fastifyMTLS = fastifyMTLS
