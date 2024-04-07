# SmbExec/ScExec

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Kako radi

**Smbexec** je alat koji se koristi za izvršavanje udaljenih komandi na Windows sistemima, slično kao **Psexec**, ali izbegava postavljanje zlonamernih fajlova na ciljni sistem.

### Ključne tačke o **SMBExec**

- Radi tako što kreira privremenu uslugu (na primer, "BTOBTO") na ciljnom računaru kako bi izvršio komande putem cmd.exe (%COMSPEC%), bez ispuštanja bilo kakvih binarnih fajlova.
- Iako koristi prikriven pristup, generiše evidencione zapise za svaku izvršenu komandu, nudeći oblik neinteraktivne "ljuske".
- Komanda za povezivanje korišćenjem **Smbexec** izgleda ovako:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Izvršavanje komandi bez binarnih fajlova

- **Smbexec** omogućava direktno izvršavanje komandi putem putanja servisa, eliminišući potrebu za fizičkim binarnim fajlovima na cilju.
- Ovaj metod je koristan za izvršavanje jednokratnih komandi na Windows cilju. Na primer, uparivanje sa Metasploit-ovim `web_delivery` modulom omogućava izvršavanje PowerShell ciljanog reverse Meterpreter payload-a.
- Kreiranjem udaljenog servisa na napadačevom računaru sa binPath postavljenim da pokrene pruženu komandu putem cmd.exe, moguće je uspešno izvršiti payload, postići povratni poziv i izvršiti payload sa Metasploit-ovim slušaocem, čak i ako dođe do grešaka u odgovoru servisa.

### Primeri komandi

Kreiranje i pokretanje servisa može se postići sledećim komandama:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
Za dodatne detalje pogledajte [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


## Reference
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
