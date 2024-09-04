# Linux Environment Variables

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

## Global variables

Globalne promenljive **će biti** nasledjene od **dečijih procesa**.

Možete kreirati globalnu promenljivu za vašu trenutnu sesiju tako što ćete:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Ova promenljiva će biti dostupna vašim trenutnim sesijama i njenim podprocesima.

Možete **ukloniti** promenljivu koristeći:
```bash
unset MYGLOBAL
```
## Lokalne promenljive

**Lokalne promenljive** mogu biti **pristupne** samo od strane **trenutne ljuske/skripte**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Lista trenutnih varijabli
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – prikaz koji koristi **X**. Ova promenljiva je obično postavljena na **:0.0**, što znači prvi prikaz na trenutnom računaru.
* **EDITOR** – korisnikov omiljeni tekstualni editor.
* **HISTFILESIZE** – maksimalan broj linija sadržanih u datoteci istorije.
* **HISTSIZE** – Broj linija dodatih u datoteku istorije kada korisnik završi svoju sesiju.
* **HOME** – vaš kućni direktorijum.
* **HOSTNAME** – ime računara.
* **LANG** – vaš trenutni jezik.
* **MAIL** – lokacija korisničkog poštanskog spremnika. Obično **/var/spool/mail/USER**.
* **MANPATH** – lista direktorijuma za pretragu priručnika.
* **OSTYPE** – tip operativnog sistema.
* **PS1** – podrazumevani prompt u bash-u.
* **PATH** – čuva putanju svih direktorijuma koji sadrže binarne datoteke koje želite da izvršite samo navodeći ime datoteke, a ne relativnu ili apsolutnu putanju.
* **PWD** – trenutni radni direktorijum.
* **SHELL** – putanja do trenutne komandne ljuske (na primer, **/bin/bash**).
* **TERM** – trenutni tip terminala (na primer, **xterm**).
* **TZ** – vaša vremenska zona.
* **USER** – vaše trenutno korisničko ime.

## Interesting variables for hacking

### **HISTFILESIZE**

Promenite **vrednost ove promenljive na 0**, tako da kada **završite svoju sesiju** **datoteka istorije** (\~/.bash\_history) **će biti obrisana**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Promenite **vrednost ove promenljive na 0**, tako da kada **završite svoju sesiju** bilo koja komanda bude dodata u **datoteku istorije** (\~/.bash\_history).
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

Procesi će koristiti **proxy** deklarisan ovde da se povežu na internet putem **http ili https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL\_CERT\_FILE & SSL\_CERT\_DIR

Procesi će verovati sertifikatima navedenim u **ovim env varijablama**.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

Promenite kako izgleda vaš prompt.

[**Ovo je primer**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../.gitbook/assets/image (897).png>)

Redovan korisnik:

![](<../.gitbook/assets/image (740).png>)

Jedan, dva i tri pozadinska zadatka:

![](<../.gitbook/assets/image (145).png>)

Jedan pozadinski zadatak, jedan zaustavljen i poslednja komanda nije završila ispravno:

![](<../.gitbook/assets/image (715).png>)


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
