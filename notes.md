# Notes to be completed for Assignment 4 (part of the assessment)

## Step 1

A: Passphrase for ca-private.pem: user_like_him

B: Password for ca-cert.jks: user_like_her


C: The CA's certificate fingerprint (SHA256) in ca-cert.jks: 05:D1:FD:53:67:85:13:99:61:BB:2D:E9:C2:23:3D:F5:BE:4F:55:C6:C9:05:2C:47:E8:4C:12:E9:B5:8A:44:8A

## Step 2

D: Passphrase for server.jks: user_like_them


E: The CA's certificate fingerprint (SHA256) in server.jks:
PrivateKeyEntry
CERTIFICATE FINGERPRINT: 2B:08:3A:58:B0:C7:19:57:81:ED:9D:CD:06:A1:F5:0D:90:79:0A:EB:E8:7A:A7:97:38:26:8B:62:8C:0C:39:F0

trustedCertEntry
CERTIFICATE FINGERPRINT: 05:D1:FD:53:67:85:13:99:61:BB:2D:E9:C2:23:3D:F5:BE:4F:55:C6:C9:05:2C:47:E8:4C:12:E9:B5:8A:44:8A

## Step 4

F: The exception from the first command:
javax.net.ssl.SSLHandshakeException: PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target

G: The exception from the second command:
javax.net.ssl.SSLHandshakeException: No name matching localhost found
