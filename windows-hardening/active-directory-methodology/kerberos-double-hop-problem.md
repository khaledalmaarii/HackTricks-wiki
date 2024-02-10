# Kerberos Double-Hop-Problem

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersecurity-Unternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**hacktricks-Repository**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud-Repository**](https://github.com/carlospolop/hacktricks-cloud) **senden**.

</details>

## Einführung

Das Kerberos "Double-Hop"-Problem tritt auf, wenn ein Angreifer versucht, die **Kerberos-Authentifizierung über zwei** **Hops** zu verwenden, zum Beispiel mit **PowerShell**/**WinRM**.

Bei einer **Authentifizierung** über **Kerberos** werden **Anmeldeinformationen** **nicht im Speicher zwischengespeichert**. Wenn Sie also mimikatz ausführen, finden Sie **keine Anmeldeinformationen** des Benutzers auf dem Computer, auch wenn er Prozesse ausführt.

Dies liegt daran, dass bei der Verbindung mit Kerberos die folgenden Schritte durchgeführt werden:

1. Benutzer1 gibt Anmeldeinformationen an und der **Domänencontroller** gibt ein Kerberos-**TGT** an Benutzer1 zurück.
2. Benutzer1 verwendet das **TGT**, um ein **Service Ticket** anzufordern, um eine Verbindung mit Server1 herzustellen.
3. Benutzer1 **verbindet** sich mit **Server1** und gibt das **Service Ticket** an.
4. **Server1** hat weder die **Anmeldeinformationen** von Benutzer1 zwischengespeichert, noch das **TGT** von Benutzer1. Daher kann sich Benutzer1 von Server1 aus nicht bei einem zweiten Server anmelden.

### Unbeschränkte Delegation

Wenn die **unbeschränkte Delegation** auf dem PC aktiviert ist, tritt dieses Problem nicht auf, da der **Server** ein **TGT** von jedem darauf zugreifenden Benutzer erhält. Darüber hinaus können Sie bei Verwendung der unbeschränkten Delegation wahrscheinlich den Domänencontroller **kompromittieren**.\
[**Weitere Informationen auf der Seite zur unbeschränkten Delegation**](unconstrained-delegation.md).

### CredSSP

Eine weitere Möglichkeit, dieses Problem zu umgehen, die [**bemerkenswert unsicher**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) ist, ist **Credential Security Support Provider** (CredSSP). Laut Microsoft:

> Bei der CredSSP-Authentifizierung werden die Benutzeranmeldeinformationen vom lokalen Computer an einen Remote-Computer delegiert. Diese Praxis erhöht das Sicherheitsrisiko der Remote-Operation. Wenn der Remote-Computer kompromittiert ist, können die Anmeldeinformationen, wenn sie an ihn übergeben werden, zur Steuerung der Netzwerksitzung verwendet werden.

Es wird dringend empfohlen, CredSSP in Produktionsumgebungen, sensiblen Netzwerken und ähnlichen Umgebungen zu deaktivieren, aufgrund von Sicherheitsbedenken. Um festzustellen, ob CredSSP aktiviert ist, kann der Befehl `Get-WSManCredSSP` ausgeführt werden. Dieser Befehl ermöglicht die **Überprüfung des CredSSP-Status** und kann sogar remote ausgeführt werden, sofern **WinRM** aktiviert ist.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Workarounds

### Invoke Command

Um das Problem des doppelten Hops anzugehen, wird eine Methode mit einer verschachtelten `Invoke-Command` vorgestellt. Dies löst das Problem nicht direkt, bietet jedoch eine Lösung ohne spezielle Konfigurationen. Der Ansatz ermöglicht die Ausführung eines Befehls (`hostname`) auf einem sekundären Server über einen PowerShell-Befehl, der von einer initialen angreifenden Maschine ausgeführt wird oder über eine zuvor etablierte PS-Session mit dem ersten Server. So wird es gemacht:
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Alternativ wird empfohlen, eine PS-Sitzung mit dem ersten Server herzustellen und `Invoke-Command` mit `$cred` auszuführen, um Aufgaben zu zentralisieren.

### PSSession-Konfiguration registrieren

Eine Lösung zur Umgehung des Double-Hop-Problems besteht darin, `Register-PSSessionConfiguration` mit `Enter-PSSession` zu verwenden. Diese Methode erfordert einen anderen Ansatz als `evil-winrm` und ermöglicht eine Sitzung, die nicht unter der Einschränkung des Double-Hop-Problems leidet.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### Portweiterleitung

Für lokale Administratoren auf einem Zwischenziel ermöglicht die Portweiterleitung das Senden von Anfragen an einen endgültigen Server. Mit `netsh` kann eine Regel für die Portweiterleitung hinzugefügt werden, zusammen mit einer Windows-Firewall-Regel, um den weitergeleiteten Port zuzulassen.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` kann verwendet werden, um WinRM-Anfragen weiterzuleiten, möglicherweise als eine weniger erkennbare Option, wenn die Überwachung von PowerShell ein Anliegen ist. Der folgende Befehl zeigt seine Verwendung:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Die Installation von OpenSSH auf dem ersten Server ermöglicht eine Lösung für das Double-Hop-Problem, was besonders nützlich für Jump-Box-Szenarien ist. Diese Methode erfordert die CLI-Installation und Konfiguration von OpenSSH für Windows. Wenn es für die Passwortauthentifizierung konfiguriert ist, ermöglicht dies dem Zwischenserver, im Namen des Benutzers ein TGT zu erhalten.

#### Schritte zur Installation von OpenSSH

1. Laden Sie das neueste OpenSSH Release-Zip herunter und verschieben Sie es auf den Zielserver.
2. Entpacken Sie es und führen Sie das Skript `Install-sshd.ps1` aus.
3. Fügen Sie eine Firewall-Regel hinzu, um Port 22 zu öffnen, und überprüfen Sie, ob die SSH-Dienste ausgeführt werden.

Um "Verbindungsreset"-Fehler zu beheben, müssen möglicherweise die Berechtigungen aktualisiert werden, um allen Lese- und Ausführungszugriff auf das OpenSSH-Verzeichnis zu ermöglichen.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Referenzen

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<details>

<summary><strong>Lernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks bewerben**? Oder möchten Sie Zugriff auf die **neueste Version von PEASS oder HackTricks im PDF-Format** haben? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**hacktricks-Repo**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud-Repo**](https://github.com/carlospolop/hacktricks-cloud) **senden.**

</details>
