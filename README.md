# example-spring-security-multiple-authentication

多用户认证体系，分为后台管理、开放接口、中台接口、app接口、基础接口认证

- /open OAuth的Client认证
- /admin 基于OAuth的AuthCode模式的SSO认证
- /app 基于C端用户的登录认证
- /middle 中台认证


```bash
curl --request GET -sL \
       -H "Authorization:Bearer eyJraWQiOiIxMjM0NTYiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJleGFtcGxlIiwiYXVkIjoiZXhhbXBsZSIsIm5iZiI6MTY3MTI5NzIyMiwic2NvcGUiOlsid3JpdGUiXSwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo5MDAwIiwiZXhwIjoxNjcxMzE4ODIyLCJpYXQiOjE2NzEyOTcyMjJ9.FvEEXiu3X4Fa1BTHwqU8eqUU9A5nkxsDeIA3QDx71XzSbj5qZdbHxfWYcH4sCiPJM8BFJq6W1JGL7Hdv3vI6ktziOvNKgXf6m64EDN9eFuitp9V1TX4wjsEAOHGSklRPukj4DgzjJocX5tJ0UOIVcDQ-dX2flNqdhJeCS107IVuTDQeIrkoxDW7LoO0diYfdDgetU2oL7q3dz4YciCUjqQuN3vTCvR5FmqxqT87bSn7sByGih6Eqy7dBLjvLH6tywL_oqFadayAY7930xiu9darQ7Baa6u2CsLcWYKFPQhpEYGwCblpXPTGDEgbkYO0HOCKREK7SttKU_sPfkzX3ig" \
     --url 'http://localhost:8010/open/index'
```


##

- https://mflash.dev/post/2020/11/15/protecting-endpoints-with-spring-security-resource-server/


##

- AuthenticationManagerResolver 用于根据提供的上下文解析 AuthenticationManager 的接口
- JwtIssuerAuthenticationManagerResolver 根据 JWT（JWE）令牌发放组织解析
- RequestMatcherDelegatingAuthenticationManagerResolver 根据请求地址解析
- StaticAuthenticationManagerResolver
- TrustedIssuerJwtAuthenticationManagerResolver


- ReactiveAuthenticationManagerResolver
- JwtIssuerReactiveAuthenticationManagerResolver
- ServerWebExchangeDelegatingReactiveAuthenticationManagerResolver
- TrustedIssuerJwtAuthenticationManagerResolver
