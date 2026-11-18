Place the mTLS files here (git-ignored):

- DEV_CA.pem  CA that signed the server certificate (added to the default JDK trust store)
- cert.pem    our client certificate (leaf first, then any intermediates)
- key.pem     private key for cert.pem, unencrypted PEM ("BEGIN PRIVATE KEY" or "BEGIN RSA PRIVATE KEY")

If a file is missing, mTLS is skipped and the JDK defaults are used.
