{% hint style="success" %}
AWSハッキングの学習と練習:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と練習: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加**するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **HackTricks**と**HackTricks Cloud**のgithubリポジトリにPRを提出して**ハッキングトリックを共有**してください。

</details>
{% endhint %}


# ECB

(ECB) Electronic Code Book - 同じブロックのクリアテキストを暗号文のブロックで**置き換える**対称暗号化スキーム。これは**最も単純な**暗号化スキームです。主なアイデアは、クリアテキストを**Nビットのブロック**（入力データのブロックサイズ、暗号化アルゴリズムに依存）に**分割**し、その後、唯一の鍵を使用して各クリアテキストブロックを暗号化（復号化）することです。

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

ECBを使用すると、複数のセキュリティ上の影響があります:

* 暗号化されたメッセージから**ブロックを削除**できる
* 暗号化されたメッセージから**ブロックを移動**できる

# 脆弱性の検出

アプリケーションに複数回ログインし、**常に同じクッキー**を取得すると想像してください。これは、アプリケーションのクッキーが**`<username>|<password>`**であるためです。\
次に、**同じ長いパスワード**を持つ新しいユーザーを2人生成し、**ほぼ**同じ**ユーザー名**を持つようにします。\
**両方のユーザーの情報**が同じ**8バイトのブロック**であることがわかります。その後、これが**ECBが使用されている**ためかもしれないと考えます。

次の例のように、これらの**2つのデコードされたクッキー**には、何度もブロック**`\x23U\xE45K\xCB\x21\xC8`**が含まれていることに注意してください。
```
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```
これは、**クッキーのユーザー名とパスワードには、複数回文字 "a" が含まれていた**ためです。**異なる**ブロックは、**少なくとも1つの異なる文字**（おそらく区切り記号 "|" またはユーザー名に必要な違い）を含んでいました。

さて、攻撃者は、フォーマットが `<ユーザー名><区切り記号><パスワード>` または `<パスワード><区切り記号><ユーザー名>` であるかどうかを見つける必要があります。そのために、彼は単に**類似して長いユーザー名とパスワードを持つ複数のユーザー名を生成**し、フォーマットと区切り記号の長さを見つけるまで続けます:

| ユーザー名の長さ: | パスワードの長さ: | ユーザー名+パスワードの長さ: | デコード後のクッキーの長さ: |
| ---------------- | ---------------- | ------------------------- | --------------------------------- |
| 2                | 2                | 4                         | 8                                 |
| 3                | 3                | 6                         | 8                                 |
| 3                | 4                | 7                         | 8                                 |
| 4                | 4                | 8                         | 16                                |
| 7                | 7                | 14                        | 16                                |

# 脆弱性の悪用

## ブロック全体の削除

クッキーのフォーマットを知っている場合（`<ユーザー名>|<パスワード>`）、ユーザー名 `admin` をなりすますために、`aaaaaaaaadmin` という新しいユーザーを作成し、クッキーを取得してデコードします:
```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
私たちは、以前に単に `a` を含むユーザー名で作成されたパターン `\x23U\xE45K\xCB\x21\xC8` を見ることができます。\
次に、最初の8Bのブロックを削除すると、ユーザー名 `admin` 用の有効なクッキーが得られます:
```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
## ブロックの移動

多くのデータベースでは、`WHERE username='admin';` を検索するのと `WHERE username='admin    ';` を検索するのは同じです（余分なスペースに注意）。

したがって、ユーザー `admin` をなりすます別の方法は次のとおりです：

- `len(<username>) + len(<delimiter) % len(block)` となるユーザー名を生成します。ブロックサイズが `8B` の場合、`username       ` というユーザー名を生成できます。デリミターが `|` の場合、チャンク `<username><delimiter>` は 2 つの 8B ブロックを生成します。
- 次に、なりすましたいユーザー名とスペースを含むブロック数を正確に埋めるパスワードを生成します。例：`admin   `

このユーザーのクッキーは 3 つのブロックで構成されます：最初の 2 つはユーザー名 + デリミターのブロックで、3 番目は（ユーザー名を偽装している）パスワードのブロックです：`username       |admin   `

**その後、最初のブロックを最後のブロックで置き換えるだけで、ユーザー `admin` をなりすませることができます：`admin          |username`**

## 参考文献

- [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](http://cryptowiki.net/index.php?title=Electronic_Code_Book_\(ECB\))
