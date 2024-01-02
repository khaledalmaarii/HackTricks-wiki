# Chemin système accessible en écriture + Élévation de privilèges par Dll Hijacking

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introduction

Si vous découvrez que vous pouvez **écrire dans un dossier du Chemin Système** (notez que cela ne fonctionnera pas si vous pouvez écrire dans un dossier du Chemin Utilisateur), il est possible que vous puissiez **élever vos privilèges** dans le système.

Pour ce faire, vous pouvez abuser d'un **Dll Hijacking** où vous allez **détourner une bibliothèque en cours de chargement** par un service ou un processus avec **plus de privilèges** que les vôtres, et parce que ce service charge une Dll qui probablement n'existe même pas dans tout le système, il va essayer de la charger depuis le Chemin Système où vous pouvez écrire.

Pour plus d'informations sur **ce qu'est le Dll Hijacking**, consultez :

{% content-ref url="../dll-hijacking.md" %}
[dll-hijacking.md](../dll-hijacking.md)
{% endcontent-ref %}

## Élévation de privilèges avec Dll Hijacking

### Trouver une Dll manquante

La première chose dont vous avez besoin est d'**identifier un processus** s'exécutant avec **plus de privilèges** que vous qui essaie de **charger une Dll depuis le Chemin Système** dans lequel vous pouvez écrire.

Le problème dans ces cas est que probablement ces processus sont déjà en cours d'exécution. Pour trouver quelles Dll manquent aux services, vous devez lancer procmon le plus tôt possible (avant que les processus ne soient chargés). Donc, pour trouver les .dll manquantes, faites :

* **Créez** le dossier `C:\privesc_hijacking` et ajoutez le chemin `C:\privesc_hijacking` à la variable d'environnement **Chemin Système**. Vous pouvez faire cela **manuellement** ou avec **PS** :
```powershell
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
* Lancez **`procmon`** et allez dans **`Options`** --> **`Activer la journalisation du démarrage`** et appuyez sur **`OK`** dans l'invite.
* Ensuite, **redémarrez**. Lorsque l'ordinateur redémarre, **`procmon`** commence à **enregistrer** les événements dès que possible.
* Une fois **Windows** démarré, exécutez **`procmon`** à nouveau, il vous informera qu'il a été en cours d'exécution et vous **demandera si vous souhaitez enregistrer** les événements dans un fichier. Dites **oui** et **enregistrez les événements dans un fichier**.
* **Après** que le **fichier** soit **généré**, **fermez** la fenêtre **`procmon`** ouverte et **ouvrez le fichier des événements**.
* Ajoutez ces **filtres** et vous trouverez toutes les DLL que certains **processus ont essayé de charger** depuis le dossier du chemin système modifiable :

<figure><img src="../../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

### DLL manquantes

En exécutant ceci dans une machine **Windows 11 virtuelle (vmware)** gratuite, j'ai obtenu ces résultats :

<figure><img src="../../../.gitbook/assets/image (253).png" alt=""><figcaption></figcaption></figure>

Dans ce cas, les .exe sont inutiles donc ignorez-les, les DLL manquantes provenaient de :

| Service                         | Dll                | Ligne de commande                                                    |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Planificateur de tâches (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Service de politique de diagnostic (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Après avoir trouvé cela, j'ai trouvé cet article de blog intéressant qui explique également comment [**abuser de WptsExtensions.dll pour l'élévation de privilèges**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll). C'est ce que nous allons **faire maintenant**.

### Exploitation

Donc, pour **élever les privilèges**, nous allons détourner la bibliothèque **WptsExtensions.dll**. Ayant le **chemin** et le **nom**, nous devons juste **générer la dll malveillante**.

Vous pouvez [**essayer d'utiliser l'un de ces exemples**](../dll-hijacking.md#creating-and-compiling-dlls). Vous pourriez exécuter des charges utiles telles que : obtenir un shell inversé, ajouter un utilisateur, exécuter un beacon...

{% hint style="warning" %}
Notez que **tous les services ne sont pas exécutés** avec **`NT AUTHORITY\SYSTEM`** certains sont également exécutés avec **`NT AUTHORITY\LOCAL SERVICE`** qui a **moins de privilèges** et vous **ne pourrez pas créer un nouvel utilisateur** pour abuser de ses permissions.\
Cependant, cet utilisateur a le privilège **`seImpersonate`**, donc vous pouvez utiliser la [**suite potato pour élever les privilèges**](../roguepotato-and-printspoofer.md). Donc, dans ce cas, un shell inversé est une meilleure option que d'essayer de créer un utilisateur.
{% endhint %}

Au moment de la rédaction, le service **Planificateur de tâches** est exécuté avec **Nt AUTHORITY\SYSTEM**.

Après avoir **généré la Dll malveillante** (_dans mon cas, j'ai utilisé un shell inversé x64 et j'ai reçu un shell mais Defender l'a tué car il provenait de msfvenom_), enregistrez-la dans le chemin système modifiable avec le nom **WptsExtensions.dll** et **redémarrez** l'ordinateur (ou redémarrez le service ou faites ce qu'il faut pour relancer le service/programme affecté).

Lorsque le service est redémarré, la **dll devrait être chargée et exécutée** (vous pouvez **réutiliser** l'astuce **procmon** pour vérifier si la **bibliothèque a été chargée comme prévu**).

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez**-moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
