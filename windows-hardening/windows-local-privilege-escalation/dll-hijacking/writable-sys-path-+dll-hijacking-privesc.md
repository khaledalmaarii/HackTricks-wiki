# Skryfbare Sys-pad + Dll-kaping Privesc

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Inleiding

As jy gevind het dat jy **kan skryf in 'n Sisteempad-vouer** (let wel dat dit nie sal werk as jy kan skryf in 'n Gebruikerspad-vouer nie) is dit moontlik dat jy **bevoorregtings kan eskaleer** in die sisteem.

Om dit te doen, kan jy 'n **Dll-kaping** misbruik waar jy 'n biblioteek wat deur 'n diens of proses met **meer bevoorregtinge** as jou gelaai word, kan **kap**. En omdat daardie diens 'n Dll laai wat waarskynlik nie eens in die hele sisteem bestaan nie, gaan dit probeer om dit van die Sisteempad te laai waar jy kan skryf.

Vir meer inligting oor **wat Dll-kaping is** kyk:

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Privesc met Dll-kaping

### Vind 'n ontbrekende Dll

Die eerste ding wat jy nodig het, is om 'n proses te **identifiseer** wat met **meer bevoorregtinge** as jy hardloop en wat probeer om 'n Dll van die Sisteempad te laai waarin jy kan skryf.

Die probleem in hierdie gevalle is dat daardie prosesse waarskynlik reeds hardloop. Om te vind watter Dlls die dienste kort, moet jy procmon so gou moontlik begin (voordat prosesse gelaai word). Dus, om ontbrekende .dlls te vind, doen die volgende:

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
* Begin deur **`procmon`** te begin en na **`Options`** te gaan --> **`Enable boot logging`** en druk **`OK`** in die venster.
* Herlaai dan die rekenaar. Wanneer die rekenaar herlaai word, sal **`procmon`** begin om gebeure so vinnig moontlik op te neem.
* Sodra **Windows** begin is, voer **`procmon`** weer uit, dit sal jou vertel dat dit aan die hardloop is en sal jou vra of jy die gebeure in 'n lêer wil stoor. Sê **ja** en **stoor die gebeure in 'n lêer**.
* **Nadat** die lêer gegenereer is, **sluit** die oop **`procmon`** venster en **open die gebeure-lêer**.
* Voeg hierdie **filters** by en jy sal al die Dlls vind wat 'n sekere proses probeer laai vanaf die skryfbare Sisteempad-vouer:

<figure><img src="../../../.gitbook/assets/image (945).png" alt=""><figcaption></figcaption></figure>

### Gemiste Dlls

Toe ek dit hardloop op 'n gratis **virtuele (vmware) Windows 11 masjien** het ek hierdie resultate gekry:

<figure><img src="../../../.gitbook/assets/image (607).png" alt=""><figcaption></figcaption></figure>

In hierdie geval is die .exe nutteloos, ignoreer hulle, die gemiste DLLs was van:

| Diens                         | Dll                | CMD lyn                                                             |
| ------------------------------- | ------------------ | -------------------------------------------------------------------- |
| Taakbeplanner (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Diagnostiese Beleid Diens (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`                |

Na hierdie ontdekking het ek hierdie interessante blogpos gevind wat ook verduidelik hoe om [**WptsExtensions.dll te misbruik vir privilige-escalation**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll). Dit is wat ons **nou gaan doen**.

### Uitbuiting

Dus, om **priviliges te eskaleer** gaan ons die biblioteek **WptsExtensions.dll** kaap. Met die **pad** en die **naam** hoef ons net die skadelike dll te **genereer**.

Jy kan [**enige van hierdie voorbeelde probeer gebruik**](./#creating-and-compiling-dlls). Jy kan payloads hardloop soos: kry 'n omgekeerde skul, voeg 'n gebruiker by, voer 'n beacon uit...

{% hint style="warning" %}
Let daarop dat **nie al die dienste met** **`NT AUTHORITY\SYSTEM`** hardloop nie, sommige hardloop ook met **`NT AUTHORITY\LOCAL SERVICE`** wat minder bevoegdhede het en jy **nie 'n nuwe gebruiker kan skep nie** om sy regte te misbruik.\
Hierdie gebruiker het egter die **`seImpersonate`** voorreg, so jy kan die [**potato suite gebruik om priviliges te eskaleer**](../roguepotato-and-printspoofer.md). Dus, in hierdie geval is 'n omgekeerde skul 'n beter opsie as om 'n gebruiker te probeer skep.
{% endhint %}

Op die oomblik van skryf word die **Taakbeplanner** diens met **Nt AUTHORITY\SYSTEM** uitgevoer.

Nadat jy die skadelike Dll gegenereer het (_in my geval het ek x64 omgekeerde skul gebruik en ek het 'n skul teruggekry, maar verdediger het dit doodgemaak omdat dit van msfvenom was_), stoor dit in die skryfbare Sisteempad met die naam **WptsExtensions.dll** en **herlaai** die rekenaar (of herlaai die diens of doen watookal dit neem om die geaffekteerde diens/program te herlaai).

Wanneer die diens herlaai word, behoort die **dll gelaai en uitgevoer te word** (jy kan die **procmon** truuk hergebruik om te kyk of die **biblioteek soos verwag gelaai is**).
