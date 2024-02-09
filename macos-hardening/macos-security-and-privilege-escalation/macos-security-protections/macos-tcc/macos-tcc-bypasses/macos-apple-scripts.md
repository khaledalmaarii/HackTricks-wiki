# Scripts Apple macOS

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Scripts Apple

Il s'agit d'un langage de script utilisé pour l'automatisation des tâches **interagissant avec des processus distants**. Il facilite la **demande à d'autres processus d'effectuer certaines actions**. **Les logiciels malveillants** peuvent exploiter ces fonctionnalités pour abuser des fonctions exportées par d'autres processus.\
Par exemple, un logiciel malveillant pourrait **injecter du code JS arbitraire dans les pages ouvertes du navigateur**. Ou **cliquer automatiquement** sur certaines autorisations demandées à l'utilisateur ;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Voici quelques exemples: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
Trouvez plus d'informations sur les logiciels malveillants utilisant des scripts Apple [**ici**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).

Les scripts Apple peuvent être facilement "**compilés**". Ces versions peuvent être facilement "**décompilées**" avec `osadecompile`

Cependant, ces scripts peuvent également être **exportés en mode "Lecture seule"** (via l'option "Exporter..."):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/.gitbook/assets/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
et dans ce cas, le contenu ne peut pas être décompilé même avec `osadecompile`

Cependant, il existe encore des outils qui peuvent être utilisés pour comprendre ce type d'exécutables, [**lisez cette recherche pour plus d'informations**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). L'outil [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) avec [**aevt\_decompile**](https://github.com/SentineLabs/aevt\_decompile) sera très utile pour comprendre comment le script fonctionne.

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks:

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF** Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** nous sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
