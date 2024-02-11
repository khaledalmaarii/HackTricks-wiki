# Skryfbare Sys-pad + Dll Hijacking Privesc

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Inleiding

As jy vind dat jy kan **skryf in 'n Sisteempad-vouer** (let daarop dat dit nie sal werk as jy kan skryf in 'n Gebruikerspad-vouer nie), is dit moontlik dat jy **voorregte kan verhoog** in die stelsel.

Om dit te doen, kan jy 'n **Dll Hijacking** misbruik waar jy 'n biblioteek wat deur 'n diens of proses met **meer voorregte** as jou gelaai word, kan **kaap**. Omdat daardie diens 'n Dll laai wat waarskynlik nie eers in die hele stelsel bestaan nie, sal dit probeer om dit van die Sisteempad te laai waarin jy kan skryf.

Vir meer inligting oor **wat Dll Hijacking is**, kyk:

{% content-ref url="../dll-hijacking.md" %}
[dll-hijacking.md](../dll-hijacking.md)
{% endcontent-ref %}

## Privesc met Dll Hijacking

### Om 'n ontbrekende Dll te vind

Die eerste ding wat jy nodig het, is om 'n proses te **identifiseer** wat met **meer voorregte** as jy loop en wat probeer om 'n Dll van die Sisteempad waarin jy kan skryf, te **laai**.

Die probleem in hierdie gevalle is dat hierdie prosesse waarskynlik alreeds loop. Om uit te vind watter Dlls die dienste kortkom, moet jy procmon so gou moontlik begin (voordat die prosesse gelaai word). Om ontbrekende .dlls te vind, doen die volgende:

* **Skep** die vouer `C:\privesc_hijacking` en voeg die pad `C:\privesc_hijacking` by die **Sisteempad-omgewingsveranderlike**. Jy kan dit **handmatig** doen of met **PS**:
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
* Begin deur **`procmon`** te open en gaan na **`Options`** --> **`Enable boot logging`** en druk **`OK`** in die venster.
* Herlaai dan die rekenaar. Wanneer die rekenaar herlaai is, sal **`procmon`** begin om gebeure op te neem.
* Wanneer Windows begin het, voer **`procmon`** weer uit. Dit sal jou vertel dat dit aan die loop was en sal jou vra of jy die gebeure in 'n lêer wil stoor. Sê **ja** en stoor die gebeure in 'n lêer.
* Nadat die lêer gegenereer is, sluit die geopende **`procmon`**-venster en open die gebeurelêer.
* Voeg hierdie **filters** by en jy sal al die Dlls vind wat deur 'n proses probeer is om vanaf die skryfbare Sisteempad-lys te laai:

<figure><img src="../../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

### Gemiste Dlls

Toe ek dit op 'n gratis virtuele (vmware) Windows 11-masjien uitgevoer het, het ek hierdie resultate gekry:

<figure><img src="../../../.gitbook/assets/image (253).png" alt=""><figcaption></figcaption></figure>

In hierdie geval is die .exe nutteloos, ignoreer hulle. Die gemiste DLLs was vanaf:

| Diens                          | Dll                | CMD-lyn                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Taakbeplanner (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostiese beleiddiens (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Nadat ek dit gevind het, het ek hierdie interessante blogpos gevind wat ook verduidelik hoe om [**WptsExtensions.dll te misbruik vir bevoorregte toegang**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll). Dit is wat ons **nou gaan doen**.

### Uitbuiting

Om dus bevoorregte toegang te verkry, gaan ons die biblioteek **WptsExtensions.dll** kap. Met die **pad** en die **naam** hoef ons net die skadelike dll te **genereer**.

Jy kan [**enige van hierdie voorbeelde probeer**](../dll-hijacking.md#creating-and-compiling-dlls). Jy kan payloads uitvoer soos: 'n omgekeerde skul, 'n gebruiker byvoeg, 'n beacon uitvoer...

{% hint style="warning" %}
Let daarop dat **nie al die dienste uitgevoer word** met **`NT AUTHORITY\SYSTEM`** nie, sommige word ook uitgevoer met **`NT AUTHORITY\LOCAL SERVICE`** wat minder bevoorregting het en jy sal nie 'n nuwe gebruiker kan skep om sy regte te misbruik nie.\
Hierdie gebruiker het egter die **`seImpersonate`**-bevoorregting, so jy kan die [**potato suite gebruik om bevoorregting te verhoog**](../roguepotato-and-printspoofer.md). In hierdie geval is 'n omgekeerde skul 'n beter opsie as om 'n gebruiker te probeer skep.
{% endhint %}

Op die oomblik van skryf word die **Taakbeplanner**-diens uitgevoer met **Nt AUTHORITY\SYSTEM**.

Nadat die skadelike Dll gegenereer is (_in my geval het ek 'n x64 omgekeerde skul gebruik en ek het 'n skul teruggekry, maar die verdediger het dit doodgemaak omdat dit van msfvenom afkomstig was_), stoor dit in die skryfbare Sisteempad met die naam **WptsExtensions.dll** en **herlaai** die rekenaar (of herlaai die diens of doen wat ook al nodig is om die betrokke diens/program te herlaai).

Wanneer die diens herlaai word, moet die dll gelaai en uitgevoer word (jy kan die **procmon**-truk hergebruik om te kyk of die biblioteek soos verwag gelaai is).

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks in PDF aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
