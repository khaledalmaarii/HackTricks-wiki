# Writable Sys Path +Dll Hijacking Privilegierhöhung

<details>

<summary>Lernen Sie AWS-Hacking von Grund auf mit <a href="https://training.hacktricks.xyz/courses/arte">htARTE (HackTricks AWS Red Team Expert)</a>!</summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

- Wenn Sie Ihr Unternehmen in HackTricks bewerben möchten oder HackTricks als PDF herunterladen möchten, überprüfen Sie die [ABONNEMENTPLÄNE](https://github.com/sponsors/carlospolop)!
- Holen Sie sich das offizielle PEASS & HackTricks-Merchandise
- Entdecken Sie die PEASS-Familie, unsere Sammlung exklusiver NFTs
- Treten Sie der Discord-Gruppe oder der Telegram-Gruppe bei oder folgen Sie uns auf Twitter
- Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die HackTricks- und HackTricks Cloud-GitHub-Repositories senden.

</details>

## Einführung

Wenn Sie feststellen, dass Sie in einem Systempfad-Ordner schreiben können (beachten Sie, dass dies nicht funktioniert, wenn Sie in einem Benutzerpfad-Ordner schreiben können), ist es möglich, dass Sie Privilegien im System eskalieren können.

Um dies zu erreichen, können Sie eine Dll-Hijacking-Methode missbrauchen, bei der Sie eine Bibliothek, die von einem Dienst oder Prozess mit höheren Privilegien geladen wird, hijacken. Da dieser Dienst eine Dll lädt, die wahrscheinlich im gesamten System nicht einmal existiert, wird er versuchen, sie aus dem Systempfad zu laden, in dem Sie schreiben können.

Weitere Informationen zum Thema Dll-Hijacking finden Sie unter:

{% content-ref url="../dll-hijacking.md" %}
[dll-hijacking.md](../dll-hijacking.md)
{% endcontent-ref %}

## Privilegierhöhung mit Dll-Hijacking

### Suche nach einer fehlenden Dll

Das erste, was Sie tun müssen, ist, einen Prozess zu identifizieren, der mit höheren Privilegien als Sie ausgeführt wird und versucht, eine Dll aus dem Systempfad zu laden, in den Sie schreiben können.

Das Problem in solchen Fällen ist, dass diese Prozesse wahrscheinlich bereits ausgeführt werden. Um herauszufinden, welche Dlls den Diensten fehlen, müssen Sie Procmon so schnell wie möglich starten (bevor die Prozesse geladen werden). Um fehlende .dlls zu finden, führen Sie folgende Schritte aus:

- Erstellen Sie den Ordner `C:\privesc_hijacking` und fügen Sie den Pfad `C:\privesc_hijacking` zur Systempfad-Umgebungsvariable hinzu. Sie können dies manuell oder mit PS tun:
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
* Starten Sie **`procmon`** und gehen Sie zu **`Optionen`** --> **`Bootprotokollierung aktivieren`** und klicken Sie auf **`OK`** in der Meldung.
* Starten Sie dann den **Computer neu**. Wenn der Computer neu gestartet wird, beginnt **`procmon`** sofort mit der Aufzeichnung von Ereignissen.
* Sobald **Windows** gestartet ist, führen Sie **`procmon`** erneut aus. Es wird Ihnen mitteilen, dass es ausgeführt wurde, und Sie fragen, ob Sie die Ereignisse in einer Datei speichern möchten. Sagen Sie **ja** und **speichern Sie die Ereignisse in einer Datei**.
* **Nachdem** die **Datei** generiert wurde, **schließen** Sie das geöffnete **`procmon`**-Fenster und **öffnen Sie die Ereignisdatei**.
* Fügen Sie diese **Filter** hinzu und Sie finden alle DLLs, die von einem **Prozess versucht wurden**, aus dem beschreibbaren Systempfad-Ordner zu laden:

<figure><img src="../../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

### Fehlende DLLs

Bei der Ausführung auf einer kostenlosen **virtuellen (VMware) Windows 11-Maschine** erhielt ich diese Ergebnisse:

<figure><img src="../../../.gitbook/assets/image (253).png" alt=""><figcaption></figcaption></figure>

In diesem Fall sind die .exe-Dateien nutzlos, also ignorieren Sie sie. Die fehlenden DLLs stammen von:

| Dienst                          | DLL                | Befehlszeile                                                        |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Aufgabenplanung (Schedule)      | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnoserichtliniendienst (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Nachdem ich dies gefunden hatte, fand ich diesen interessanten Blog-Beitrag, der auch erklärt, wie man [**WptsExtensions.dll für Privilege Escalation missbraucht**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll). Das ist es, was wir jetzt tun werden.

### Ausnutzung

Um also Privilegien zu **eskalierten**, werden wir die Bibliothek **WptsExtensions.dll** hijacken. Wenn wir den **Pfad** und den **Namen** haben, müssen wir nur die bösartige DLL generieren.

Sie können [**eines dieser Beispiele verwenden**](../dll-hijacking.md#creating-and-compiling-dlls). Sie könnten Payloads ausführen wie: eine Reverse-Shell erhalten, einen Benutzer hinzufügen, einen Beacon ausführen...

{% hint style="warning" %}
Beachten Sie, dass **nicht alle Dienste** mit **`NT AUTHORITY\SYSTEM`** ausgeführt werden, einige werden auch mit **`NT AUTHORITY\LOCAL SERVICE`** ausgeführt, der **weniger Privilegien** hat und Sie **keinen neuen Benutzer erstellen können**, um seine Berechtigungen zu missbrauchen.\
Dieser Benutzer hat jedoch das **`seImpersonate`**-Privileg, sodass Sie die [**Potato Suite zur Privilege Escalation verwenden können**](../roguepotato-and-printspoofer.md). In diesem Fall ist eine Reverse-Shell eine bessere Option als der Versuch, einen Benutzer zu erstellen.
{% endhint %}

Zum Zeitpunkt des Schreibens wird der Dienst **Aufgabenplanung** mit **Nt AUTHORITY\SYSTEM** ausgeführt.

Nachdem Sie die bösartige DLL generiert haben (_in meinem Fall habe ich eine x64 Reverse-Shell verwendet und eine Shell erhalten, aber der Defender hat sie getötet, weil sie von msfvenom stammte_), speichern Sie sie im beschreibbaren Systempfad mit dem Namen **WptsExtensions.dll** und **starten Sie den Computer neu** (oder starten Sie den Dienst neu oder tun Sie, was auch immer erforderlich ist, um den betroffenen Dienst/Programm erneut auszuführen).

Wenn der Dienst neu gestartet wird, sollte die **DLL geladen und ausgeführt** werden (Sie können den **procmon**-Trick erneut verwenden, um zu überprüfen, ob die **Bibliothek wie erwartet geladen** wurde).

<details>

<summary><strong>Erlernen Sie das Hacken von AWS von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks bewerben möchten** oder **HackTricks als PDF herunterladen** möchten, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegramm-Gruppe**](https://t.me/peass) bei oder folgen Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **GitHub-Repositories** senden.

</details>
