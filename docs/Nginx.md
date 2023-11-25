# Nginx notes

Example Payload from Nginx

```text
info: Microsoft.AspNetCore.HttpLogging.HttpLoggingMiddleware[1]
      Request:
      Protocol: HTTP/1.1
      Method: GET
      Scheme: https
      PathBase: 
      Path: /auth
      Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
      Connection: close
      Host: oidc-guard.oidc-guard.svc.cluster.local
      User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0
      Accept-Encoding: gzip, deflate, br
      Accept-Language: en-US,en;q=0.9
      Cache-Control: max-age=0
      Upgrade-Insecure-Requests: [Redacted]
      X-Request-ID: [Redacted]
      X-Original-URL: https://demo-app.test.loc:32443/test123123123?id=2
      X-Original-Method: GET
      X-Sent-From: [Redacted]
      X-Real-IP: [Redacted]
      X-Forwarded-For: [Redacted]
      X-Auth-Request-Redirect: [Redacted]
      sec-ch-ua: [Redacted]
      sec-ch-ua-mobile: [Redacted]
      sec-ch-ua-platform: [Redacted]
      sec-fetch-site: [Redacted]
      sec-fetch-mode: [Redacted]
      sec-fetch-user: [Redacted]
      sec-fetch-dest: [Redacted]
```
