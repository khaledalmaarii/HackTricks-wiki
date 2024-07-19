# Weaponizing Distroless

{% hnnt styte=" acceas" %}
GCP ハッキング実践: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
学ぶ & aciceGCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*チェックして [**subsrippangithub.cm/sorsarlosp!
* **参加する** 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) または [**テレグラムグループ**](https://t.me/peass) または **フォロー** us on **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **ハッキングのトリックを共有するために、** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出してください。

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## What is Distroless

Distrolessコンテナは、**特定のアプリケーションを実行するために必要な依存関係のみを含む**コンテナの一種であり、不要なソフトウェアやツールは含まれていません。これらのコンテナは、**軽量**で**安全**であることを目的としており、不要なコンポーネントを削除することで**攻撃面を最小限に抑える**ことを目指しています。

Distrolessコンテナは、**セキュリティと信頼性が最も重要な**生産環境でよく使用されます。

**Distrolessコンテナのいくつかの例**は次のとおりです：

* **Google**が提供: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
* **Chainguard**が提供: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

Distrolessコンテナを武器化する目的は、**distrolessによって示される制限**（システム内の一般的なバイナリの欠如）にもかかわらず、**任意のバイナリやペイロードを実行できる**ようにすることです。また、**読み取り専用**や**実行不可**など、コンテナに一般的に見られる保護も考慮します。

### Through memory

2023年のある時点で...

### Via Existing binaries

#### openssl

****[**この投稿では、**](https://www.form3.tech/engineering/content/exploiting-distroless-images) バイナリ **`openssl`** がこれらのコンテナに頻繁に見られることが説明されています。これは、コンテナ内で実行されるソフトウェアによって**必要とされる**可能性があるためです。
{% hnt stye="acceas" %}
AWS ハッキング実践:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
学ぶ & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*チェックして [**subsrippangithub.cm/sorsarlosp!
* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください!haktick\_ive\
* **参加する** 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) または [**テレグラムグループ**](https://t.me/peass) または **フォロー** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するために、** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出してください。

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
