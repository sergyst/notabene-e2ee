Place the mTLS files here (git-ignored):

- cacerts_dev.jks  JKS truststore (password: notabene.tls.truststore-password); added to the default JDK trust store
- cert.pem    our client certificate (leaf first, then any intermediates)
- key.pem     private key for cert.pem, unencrypted PEM ("BEGIN PRIVATE KEY" or "BEGIN RSA PRIVATE KEY")

If a file is missing, mTLS is skipped and the JDK defaults are used.
