# micro-security-sample

マイクロサービスパターン 第11章 におけるマイクロサービスでの認証の golang 実装例（すごく簡易）です。
※ 動作には, GCP より OAuth 認証設定が必要です。

本より引用

>どのアプローチで実装するにしても大切なこと
> - APIゲートウェイがクライアントの認証を担当する
> - APIゲートウェイとサービスは、主体についての情報を受け渡しするために JWT などのトランスペアレントトークンを使う
> - サービスはトークンを使って主体のIDなどを入手する

ということで本サンプルではフレームワークを用いず, 上記実装で大切なことを極力守った素の実装になります。

![名称未設定](https://user-images.githubusercontent.com/10706586/113572877-0037ac80-9654-11eb-9960-95cd8a0ab169.png)

### API ゲートウェイとクライアントの認証

OAuth2.0 Google 実装には, golang.org/x/oauth2 を利用。 `/auth/google` から認証用URLの作成。認証URLからコールバックで各種トークン取得。

```
❯ curl -i http://localhost:3000/auth/google
HTTP/1.1 200 OK
Date: Mon, 05 Apr 2021 11:29:22 GMT
Content-Length: 0
...
...
2021/04/05 20:29:26 TokenType= Bearer
2021/04/05 20:29:26 AccessToken= ******
2021/04/05 20:29:26 Expiry= 2021-04-05T21:29:25+09:00
2021/04/05 20:29:26 RefreshToken= 
2021/04/05 20:29:26 UserId= ******
```

アクセストークンをクッキーにのせた想定でのリクエスト

```
❯ access=****
...
...
❯ curl -i -b "access_token=${access};" -X POST http://localhost:3000/v1/orders/dummy
HTTP/1.1 200 OK
Date: Mon, 05 Apr 2021 11:30:02 GMT
Content-Length: 0
```

### API ゲートウェイとサービスとの認証 (JWT)

`github.com/dgrijalva/jwt-go` での実装。サービスに伝えるための userID を claims に含める形での実装。
（本には ID やロールなどとあったため, 本来ロールも含めてもいいのかも）

## 動いてるとこ

https://user-images.githubusercontent.com/10706586/113572432-26a91800-9653-11eb-9b70-b5e5a681ca5c.mov
