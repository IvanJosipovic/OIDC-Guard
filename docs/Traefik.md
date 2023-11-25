# Traefik notes

Example Payload from Traefik

```text
info: Microsoft.AspNetCore.HttpLogging.HttpLoggingMiddleware[1]
      Request:
      Protocol: HTTP/1.1
      Method: GET
      Scheme: https
      PathBase: 
      Path: /auth
      Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
      Host: oidc-guard.oidc-guard.svc.cluster.local:8080
      User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0
      Accept-Encoding: gzip, deflate, br
      Accept-Language: en-US,en;q=0.9
      Cache-Control: max-age=0
      Upgrade-Insecure-Requests: [Redacted]
      Sec-Ch-Ua: [Redacted]
      Sec-Ch-Ua-Mobile: [Redacted]
      Sec-Ch-Ua-Platform: [Redacted]
      Sec-Fetch-Dest: [Redacted]
      Sec-Fetch-Mode: [Redacted]
      Sec-Fetch-Site: [Redacted]
      Sec-Fetch-User: [Redacted]
      X-Forwarded-For: [Redacted]
      X-Forwarded-Host: demo-app.test.loc:32443
      X-Forwarded-Method: GET
      X-Forwarded-Port: [Redacted]
      X-Forwarded-Proto: https
      X-Forwarded-Server: [Redacted]
      X-Forwarded-Uri: /test123123123?id=2
      X-Real-Ip: [Redacted]
```
