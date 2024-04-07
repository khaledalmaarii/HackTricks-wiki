# Abus de processus macOS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

- Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
- Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
- **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
- **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Abus de processus macOS

macOS, comme tout autre système d'exploitation, propose une variété de méthodes et mécanismes pour que les **processus interagissent, communiquent et partagent des données**. Bien que ces techniques soient essentielles pour le bon fonctionnement du système, elles peuvent également être abusées par des acteurs malveillants pour **effectuer des activités malveillantes**.

### Injection de bibliothèque

L'injection de bibliothèque est une technique dans laquelle un attaquant **force un processus à charger une bibliothèque malveillante**. Une fois injectée, la bibliothèque s'exécute dans le contexte du processus cible, fournissant à l'attaquant les mêmes autorisations et accès que le processus.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### Accrochage de fonction

L'accrochage de fonction implique **l'interception des appels de fonction** ou des messages au sein d'un code logiciel. En accrochant des fonctions, un attaquant peut **modifier le comportement** d'un processus, observer des données sensibles, voire prendre le contrôle du flux d'exécution.

{% content-ref url="macos-function-hooking.md" %}
[macos-function-hooking.md](macos-function-hooking.md)
{% endcontent-ref %}

### Communication inter-processus

La communication inter-processus (IPC) fait référence à différentes méthodes par lesquelles des processus distincts **partagent et échangent des données**. Bien que l'IPC soit fondamental pour de nombreuses applications légitimes, il peut également être utilisé de manière abusive pour contourner l'isolation des processus, divulguer des informations sensibles ou effectuer des actions non autorisées.

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Injection d'applications Electron

Les applications Electron exécutées avec des variables d'environnement spécifiques pourraient être vulnérables à l'injection de processus :

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### Injection Chromium

Il est possible d'utiliser les indicateurs `--load-extension` et `--use-fake-ui-for-media-stream` pour effectuer une **attaque de l'homme du navigateur** permettant de voler des frappes, du trafic, des cookies, d'injecter des scripts dans les pages... :

{% content-ref url="macos-chromium-injection.md" %}
[macos-chromium-injection.md](macos-chromium-injection.md)
{% endcontent-ref %}

### Fichier NIB corrompu

Les fichiers NIB **définissent les éléments de l'interface utilisateur (UI)** et leurs interactions au sein d'une application. Cependant, ils peuvent **exécuter des commandes arbitraires** et **Gatekeeper n'empêche pas** l'exécution d'une application déjà exécutée si un **fichier NIB est modifié**. Par conséquent, ils pourraient être utilisés pour faire exécuter des programmes arbitraires des commandes arbitraires :

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Injection d'applications Java

Il est possible d'abuser de certaines capacités de Java (comme la variable d'environnement **`_JAVA_OPTS`**) pour faire exécuter à une application Java du **code/commandes arbitraires**.

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md](macos-java-apps-injection.md)
{% endcontent-ref %}

### Injection d'applications .Net

Il est possible d'injecter du code dans des applications .Net en **abusant de la fonctionnalité de débogage .Net** (non protégée par les protections macOS telles que le renforcement de l'exécution).

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Injection Perl

Consultez différentes options pour faire exécuter du code arbitraire dans un script Perl :

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md](macos-perl-applications-injection.md)
{% endcontent-ref %}

### Injection Ruby

Il est également possible d'abuser des variables d'environnement Ruby pour faire exécuter des scripts arbitraires :

{% content-ref url="macos-ruby-applications-injection.md" %}
[macos-ruby-applications-injection.md](macos-ruby-applications-injection.md)
{% endcontent-ref %}

### Injection Python

Si la variable d'environnement **`PYTHONINSPECT`** est définie, le processus Python passera en mode CLI Python une fois terminé. Il est également possible d'utiliser **`PYTHONSTARTUP`** pour indiquer un script Python à exécuter au début d'une session interactive.\
Cependant, notez que le script **`PYTHONSTARTUP`** ne sera pas exécuté lorsque **`PYTHONINSPECT`** crée la session interactive.

D'autres variables d'environnement telles que **`PYTHONPATH`** et **`PYTHONHOME`** pourraient également être utiles pour faire exécuter du code arbitraire par une commande Python.

Notez que les exécutables compilés avec **`pyinstaller`** n'utiliseront pas ces variables d'environnement même s'ils s'exécutent à l'aide d'un Python intégré.

{% hint style="danger" %}
Dans l'ensemble, je n'ai pas trouvé de moyen de faire exécuter du code arbitraire par Python en abusant des variables d'environnement.\
Cependant, la plupart des gens installent Python en utilisant **Hombrew**, qui installera Python dans un **emplacement inscriptible** pour l'utilisateur administrateur par défaut. Vous pouvez le détourner avec quelque chose comme:
```bash
mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
cat > /opt/homebrew/bin/python3 <<EOF
#!/bin/bash
# Extra hijack code
/opt/homebrew/bin/python3.old "$@"
EOF
chmod +x /opt/homebrew/bin/python3
```
## Détection

### Shield

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) est une application open source qui peut **détecter et bloquer les actions d'injection de processus** :

* En utilisant les **Variables d'Environnement** : Il surveillera la présence de l'une des variables d'environnement suivantes : **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** et **`ELECTRON_RUN_AS_NODE`**
* En utilisant les appels **`task_for_pid`** : Pour trouver quand un processus veut obtenir le **port de tâche d'un autre** ce qui permet d'injecter du code dans le processus.
* **Paramètres des applications Electron** : Quelqu'un peut utiliser les arguments de ligne de commande **`--inspect`**, **`--inspect-brk`** et **`--remote-debugging-port`** pour démarrer une application Electron en mode débogage, et ainsi injecter du code.
* En utilisant des **liens symboliques** ou des **liens physiques** : Typiquement, l'abus le plus courant est de **placer un lien avec nos privilèges utilisateur**, et de **le pointer vers un emplacement de privilège supérieur**. La détection est très simple pour les liens symboliques et physiques. Si le processus créant le lien a un **niveau de privilège différent** du fichier cible, nous créons une **alerte**. Malheureusement, dans le cas des liens symboliques, le blocage n'est pas possible, car nous n'avons pas d'informations sur la destination du lien avant sa création. Il s'agit d'une limitation du framework EndpointSecuriy d'Apple.

### Appels effectués par d'autres processus

Dans [**cet article de blog**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) vous pouvez trouver comment il est possible d'utiliser la fonction **`task_name_for_pid`** pour obtenir des informations sur d'autres **processus injectant du code dans un processus** et ensuite obtenir des informations sur cet autre processus.

Notez que pour appeler cette fonction, vous devez être **le même uid** que celui exécutant le processus ou **root** (et cela renvoie des informations sur le processus, pas un moyen d'injecter du code).

## Références

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
