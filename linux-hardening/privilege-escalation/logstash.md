{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}


## Logstash

Logstashは**ログを収集、変換、配信する**ために使用されます。このシステムは**パイプライン**として知られています。これらのパイプラインは**入力**、**フィルター**、および**出力**のステージで構成されています。Logstashが侵害されたマシンで動作する際に興味深い側面が現れます。

### パイプライン設定

パイプラインは**/etc/logstash/pipelines.yml**ファイルで設定されており、パイプライン設定の場所がリストされています：
```yaml
# Define your pipelines here. Multiple pipelines can be defined.
# For details on multiple pipelines, refer to the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
path.config: "/usr/share/logstash/pipeline/1*.conf"
pipeline.workers: 6
```
このファイルは、パイプライン構成を含む **.conf** ファイルの場所を明らかにします。**Elasticsearch output module** を使用する際、**pipelines** には **Elasticsearch credentials** が含まれることが一般的で、これは Logstash が Elasticsearch にデータを書き込む必要があるため、しばしば広範な権限を持っています。構成パスのワイルドカードにより、Logstash は指定されたディレクトリ内のすべての一致するパイプラインを実行できます。

### 書き込み可能なパイプラインによる特権昇格

特権昇格を試みるには、まず Logstash サービスが実行されているユーザー、通常は **logstash** ユーザーを特定します。次の **いずれか** の条件を満たしていることを確認してください：

- パイプライン **.conf** ファイルへの **書き込みアクセス** を持っている **または**
- **/etc/logstash/pipelines.yml** ファイルがワイルドカードを使用しており、ターゲットフォルダーに書き込むことができる

さらに、次の **いずれか** の条件を満たす必要があります：

- Logstash サービスを再起動する能力 **または**
- **/etc/logstash/logstash.yml** ファイルに **config.reload.automatic: true** が設定されている

構成にワイルドカードがある場合、このワイルドカードに一致するファイルを作成することでコマンドを実行できます。例えば：
```bash
input {
exec {
command => "whoami"
interval => 120
}
}

output {
file {
path => "/tmp/output.log"
codec => rubydebug
}
}
```
ここで、**interval**は実行頻度を秒単位で決定します。与えられた例では、**whoami**コマンドが120秒ごとに実行され、その出力は**/tmp/output.log**に送られます。

**/etc/logstash/logstash.yml**に**config.reload.automatic: true**が設定されている場合、Logstashは再起動することなく新しいまたは変更されたパイプライン設定を自動的に検出して適用します。ワイルドカードがない場合でも、既存の設定に対して変更を加えることは可能ですが、中断を避けるために注意が必要です。

## 参考文献
{% hint style="success" %}
AWSハッキングを学び、実践する：<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングを学び、実践する：<img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksをサポートする</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください！
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
