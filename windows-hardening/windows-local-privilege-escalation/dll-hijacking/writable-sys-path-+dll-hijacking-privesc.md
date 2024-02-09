# Chemin Sys inscriptible + Privilège d'escalade Dll Hijacking

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>

## Introduction

Si vous découvrez que vous pouvez **écrire dans un dossier de chemin système** (notez que cela ne fonctionnera pas si vous pouvez écrire dans un dossier de chemin utilisateur), il est possible que vous puissiez **escalader les privilèges** dans le système.

Pour ce faire, vous pouvez abuser d'un **Hijacking de Dll** où vous allez **détourner une bibliothèque en cours de chargement** par un service ou un processus avec **plus de privilèges** que les vôtres, et parce que ce service charge une Dll qui n'existe probablement même pas dans tout le système, il va essayer de la charger à partir du chemin système où vous pouvez écrire.

Pour plus d'informations sur **ce qu'est le Dll Hijacking**, consultez :

{% content-ref url="../dll-hijacking.md" %}
[dll-hijacking.md](../dll-hijacking.md)
{% endcontent-ref %}

## Privilège d'escalade avec Dll Hijacking

### Trouver une Dll manquante

La première chose dont vous avez besoin est d'**identifier un processus** s'exécutant avec **plus de privilèges** que les vôtres qui tente de **charger une Dll à partir du chemin système** dans lequel vous pouvez écrire.

Le problème dans ces cas est que probablement ces processus sont déjà en cours d'exécution. Pour trouver quelles Dll manquent aux services, vous devez lancer procmon dès que possible (avant le chargement des processus). Ainsi, pour trouver les .dll manquantes, faites :

* **Créez** le dossier `C:\privesc_hijacking` et ajoutez le chemin `C:\privesc_hijacking` à la **variable d'environnement du chemin système**. Vous pouvez le faire **manuellement** ou avec **PS** :
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
* Lancez **`procmon`** et allez dans **`Options`** --> **`Activer l'enregistrement au démarrage`** et appuyez sur **`OK`** dans la fenêtre qui s'affiche.
* Ensuite, **redémarrez**. Lorsque l'ordinateur redémarre, **`procmon`** commencera à enregistrer les événements dès que possible.
* Une fois que **Windows** est **démarré, exécutez `procmon`** à nouveau, il vous indiquera qu'il était en cours d'exécution et vous **demandera si vous souhaitez enregistrer** les événements dans un fichier. Dites **oui** et **enregistrez les événements dans un fichier**.
* **Après** la **génération du fichier**, **fermez** la fenêtre **`procmon`** ouverte et **ouvrez le fichier des événements**.
* Ajoutez ces **filtres** et vous trouverez toutes les DLL que certains **processus ont tenté de charger** à partir du dossier Chemin système inscriptible :

<figure><img src="../../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

### DLLs manquantes

En exécutant ceci dans une **machine virtuelle (vmware) Windows 11** gratuite, j'ai obtenu ces résultats :

<figure><img src="../../../.gitbook/assets/image (253).png" alt=""><figcaption></figcaption></figure>

Dans ce cas, les .exe sont inutiles, ignorez-les, les DLL manquantes provenaient de :

| Service                         | Dll                | Ligne de commande                                                   |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Planificateur de tâches (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Service de stratégie de diagnostic (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Après avoir trouvé cela, j'ai trouvé ce billet de blog intéressant qui explique également comment [**abuser de WptsExtensions.dll pour l'élévation de privilèges**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll). Ce que nous **allons faire maintenant**.

### Exploitation

Donc, pour **élever les privilèges**, nous allons détourner la bibliothèque **WptsExtensions.dll**. Ayant le **chemin** et le **nom**, nous devons simplement **générer la DLL malveillante**.

Vous pouvez [**essayer d'utiliser l'un de ces exemples**](../dll-hijacking.md#creating-and-compiling-dlls). Vous pourriez exécuter des charges utiles telles que : obtenir un shell inversé, ajouter un utilisateur, exécuter un beacon...

{% hint style="warning" %}
Notez que **tous les services ne sont pas exécutés** avec **`NT AUTHORITY\SYSTEM`**, certains sont également exécutés avec **`NT AUTHORITY\LOCAL SERVICE`** qui a **moins de privilèges** et vous **ne pourrez pas créer un nouvel utilisateur** pour abuser de ses autorisations.\
Cependant, cet utilisateur a le privilège **`seImpersonate`**, vous pouvez donc utiliser la [**suite potato pour élever les privilèges**](../roguepotato-and-printspoofer.md). Ainsi, dans ce cas, un shell inversé est une meilleure option que d'essayer de créer un utilisateur.
{% endhint %}

Au moment de l'écriture, le service **Planificateur de tâches** est exécuté avec **Nt AUTHORITY\SYSTEM**.

Après avoir **généré la DLL malveillante** (_dans mon cas, j'ai utilisé un shell inversé x64 et j'ai obtenu un shell, mais Defender l'a tué car il provenait de msfvenom_), enregistrez-la dans le Chemin système inscriptible avec le nom **WptsExtensions.dll** et **redémarrez** l'ordinateur (ou redémarrez le service ou faites ce qu'il faut pour relancer le service/programme affecté).

Lorsque le service est redémarré, la **DLL devrait être chargée et exécutée** (vous pouvez **réutiliser** l'astuce **procmon** pour vérifier si la **bibliothèque a été chargée comme prévu**).
