Place the mTLS files here (git-ignored):

- cacerts_dev.jks  JKS truststore (password: notabene.tls.truststore-password); added to the default JDK trust store
- client.p12       PKCS#12 with our client certificate + private key (password: notabene.tls.keystore-password)

Rename client.p12 or change notabene.tls.keystore if your file is called something else.
If a file is missing, it is skipped and the JDK defaults are used.
