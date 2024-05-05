# Beschreibbarer Sys-Pfad + Dll-Hijacking-Privesc

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks als PDF herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories senden.

</details>

## Einführung

Wenn Sie feststellen, dass Sie in einem **Systempfadordner schreiben können** (beachten Sie, dass dies nicht funktioniert, wenn Sie in einem Benutzerpfadordner schreiben können), ist es möglich, dass Sie **Berechtigungen eskalieren** können.

Um dies zu erreichen, können Sie ein **Dll-Hijacking** missbrauchen, bei dem Sie eine Bibliothek **kapern, die von einem Dienst oder Prozess mit** mehr Berechtigungen **geladen wird als Sie, und da dieser Dienst eine Dll lädt, die wahrscheinlich im gesamten System nicht einmal existiert, wird er versuchen, sie aus dem Systempfad zu laden, in den Sie schreiben können.

Für weitere Informationen zum **Dll-Hijacking** siehe:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Privesc mit Dll-Hijacking

### Auffinden einer fehlenden Dll

Das erste, was Sie benötigen, ist die **Identifizierung eines Prozesses**, der mit **mehr Berechtigungen** als Sie läuft und versucht, eine Dll aus dem Systempfad zu laden, in den Sie schreiben können.

Das Problem in diesen Fällen ist, dass diese Prozesse wahrscheinlich bereits ausgeführt werden. Um herauszufinden, welche Dlls den Diensten fehlen, müssen Sie procmon so schnell wie möglich starten (bevor Prozesse geladen werden). Um fehlende .dlls zu finden, tun Sie Folgendes:

* **Erstellen** Sie den Ordner `C:\privesc_hijacking` und fügen Sie den Pfad `C:\privesc_hijacking` der **Systempfad-Umgebungsvariable** hinzu. Sie können dies **manuell** oder mit **PS** tun:
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
* Starten Sie **`procmon`** und gehen Sie zu **`Optionen`** --> **`Bootprotokollierung aktivieren`** und drücken Sie **`OK`** in der Aufforderung.
* **Starten** Sie dann den **Computer neu**. Wenn der Computer neu gestartet wird, wird **`procmon`** sofort mit der **Aufzeichnung von Ereignissen beginnen**.
* Sobald **Windows** gestartet ist, führen Sie **`procmon`** erneut aus. Es wird Ihnen mitteilen, dass es ausgeführt wurde, und Sie **fragen, ob Sie die Ereignisse in einer Datei speichern möchten**. Sagen Sie **ja** und **speichern Sie die Ereignisse in einer Datei**.
* **Nachdem** die **Datei generiert wurde**, **schließen** Sie das geöffnete **`procmon`**-Fenster und **öffnen Sie die Ereignisdatei**.
* Fügen Sie diese **Filter** hinzu und Sie finden alle Dlls, die von einem **Prozess versucht wurden, aus dem beschreibbaren Systempfadordner zu laden**:

<figure><img src="../../../.gitbook/assets/image (945).png" alt=""><figcaption></figcaption></figure>

### Fehlende Dlls

Bei der Ausführung auf einer kostenlosen **virtuellen (vmware) Windows 11-Maschine** erhielt ich diese Ergebnisse:

<figure><img src="../../../.gitbook/assets/image (607).png" alt=""><figcaption></figcaption></figure>

In diesem Fall sind die .exe nutzlos, also ignorieren Sie sie. Die fehlenden DLLs stammen von:

| Dienst                         | Dll                | Befehlszeile                                                        |
| ------------------------------- | ------------------ | ------------------------------------------------------------------- |
| Taskplaner (Schedule)          | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnoserichtliniendienst (DPS)| Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                            | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Nachdem ich dies gefunden hatte, fand ich diesen interessanten Blogbeitrag, der auch erklärt, wie man [**WptsExtensions.dll für Privilege Escalation missbrauchen kann**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll). Das ist es, was wir **jetzt tun werden**.

### Ausnutzung

Um **Berechtigungen zu eskalieren**, werden wir die Bibliothek **WptsExtensions.dll hijacken**. Nachdem wir den **Pfad** und den **Namen** haben, müssen wir nur die **bösartige DLL generieren**.

Sie können [**versuchen, eines dieser Beispiele zu verwenden**](./#creating-and-compiling-dlls). Sie könnten Payloads ausführen wie: eine Reverse-Shell erhalten, einen Benutzer hinzufügen, einen Beacon ausführen...

{% hint style="warning" %}
Beachten Sie, dass **nicht alle Dienste** mit **`NT AUTHORITY\SYSTEM`** ausgeführt werden, einige werden auch mit **`NT AUTHORITY\LOCAL SERVICE`** ausgeführt, der **weniger Berechtigungen** hat und Sie **keinen neuen Benutzer erstellen können** missbrauchen Sie seine Berechtigungen.\
Allerdings hat dieser Benutzer das **`seImpersonate`**-Privileg, sodass Sie die [**Potato Suite zur Eskalation von Berechtigungen verwenden können**](../roguepotato-and-printspoofer.md). In diesem Fall ist eine Reverse-Shell eine bessere Option als der Versuch, einen Benutzer zu erstellen.
{% endhint %}

Zum Zeitpunkt des Schreibens wird der **Taskplaner**-Dienst mit **Nt AUTHORITY\SYSTEM** ausgeführt.

Nachdem Sie die **bösartige DLL generiert** haben (in meinem Fall habe ich eine x64 Reverse-Shell verwendet und eine Shell erhalten, aber Defender hat sie getötet, weil sie von msfvenom stammte), speichern Sie sie im beschreibbaren Systempfad mit dem Namen **WptsExtensions.dll** und **starten Sie den Computer neu** (oder starten Sie den Dienst neu oder tun Sie, was auch immer erforderlich ist, um den betroffenen Dienst/das betroffene Programm erneut auszuführen).

Wenn der Dienst neu gestartet wird, sollte die **DLL geladen und ausgeführt werden** (Sie können den **procmon**-Trick **wieder verwenden**, um zu überprüfen, ob die **Bibliothek wie erwartet geladen wurde**).
