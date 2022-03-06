# Kong Certificate Upstream Plugin

A prototype of a [Kong](https://konghq.com/kong/) Plugin for x509 certificate based authentication for upstream system. The prototype was built to provide a principal propagation for SAP ABAP Application Server. The idea is that client's identity gets validated using any of the Kong's plugins (e.g., OIDC) and then a short-term x509 certificate is generated and send to the upstream system. The upstream system uses it to authenticate call and therefore it needs to trust the certificate that is used to sign these short-term client certificates. This approach is used by SAP Cloud Connector for principal propagation from SAP BTP environment down to SAP system based on ABAP AS.

The plugin is written in Javascript. The main part is generation of x509 certificates. This is done using npm package [node-forge](https://www.npmjs.com/package/node-forge). As OpenSSL bindings are available in Lua, it should be relatively straightforward to rewrite it to a native Lua based plugin.

## Configuration

The plugin supports the following configuration options.

| Attribute          | Default Value   | Description                                                                                                                                                                            |
| ------------------ | --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| private_key        | N/A             | Path to a private key file in PEM format that will be used to sign generated x509 certs                                                                                                |
| cert               | N/A             | Path to a certificate file in PEM format that will be used to sign generated x509 certs                                                                                                |
| cert_validity_secs | 300             | Validity period in seconds of generated x509 cert                                                                                                                                      |
| http_header_name   | ssl_client_cert | Name of the HTTP header attribute that will contain the generated base64 encoded x509 cert                                                                                             |
| fixed_identity     | N/A             | if specified, this is the identity that will be used to generate x509 certificate. An example would be a scenario where a technical user is used for authentication in upstream system |
| no_cert_cache      | false           | If set to true, the generated x509 certs are not cached. Every call will generate a new certificate                                                                                    |
