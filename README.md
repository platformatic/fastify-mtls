# fastify-mtls

It will set up TLS on a fastify server, using Vault as CA with [`vault-pki-fetcher`](https://github.com/platformatic/vault-pki-fetcher)

## Usage

```javascript
const fastify = require('fastify')
const mtlsPlugin = require('fastify-mtls')

const server = fastify({
    https: {
      key: '',
      cert: '',
      requestCert: true,
      rejectUnauthorized: true
    }
  })
server.register(mtlsPlugin, mtlsOptions)
const mtlsOptions = {
  vaultNamespace: 'admin',
  vaultAddress: 'http://localhost:8200',
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
await server.listen({ port: 0 })
console.log(server.mtls) // { ca: '...', cert: '...', key: '...' }
```

## License

Apache 2.0