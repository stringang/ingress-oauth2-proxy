# ingress-oauth2-proxy

使用 oauth2-proxy 对 ingress 进行 oidc 认证。可扩展对接 k8s RBAC 进行权限控制

## oauth-proxy

```shell
reverse_proxy = true
whitelist_domains = ["*.example.com"]
# 使用 cookie 存储 session 信息
cookie_secure = false
cookie_domains = [".example.cn"]
cookie_samesite = "lax"
```

## ingress

```shell
# rd 参数表示认证成功后客户端重定向地址，oauth2-proxy 也支持从 headers 参数获取
nginx.ingress.kubernetes.io/auth-signin: 'http://oauth2-proxy.example.com/oauth2/start?rd=$scheme://$host$request_uri'
nginx.ingress.kubernetes.io/auth-url: 'http://oauth2-proxy.oauth2-proxy.svc.cluster.local/oauth2/auth'
```

## Reference
- [OAuth 2.0 Authorization Code Flow](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow)
- [Ingress External OAUTH Authentication](https://kubernetes.github.io/ingress-nginx/examples/auth/oauth-external-auth/)
- [nginx-oauth2-proxy-demo](https://github.com/deskoh/nginx-oauth2-proxy-demo)