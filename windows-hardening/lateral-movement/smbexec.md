# SmbExec/ScExec

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>

## Hoe dit werk

**Smbexec** is 'n gereedskap wat gebruik word vir afgeleë beveluitvoering op Windows-stelsels, soortgelyk aan **Psexec**, maar dit vermy om enige skadelike lêers op die teikensisteem te plaas.

### Sleutelpunte oor **SMBExec**

- Dit werk deur 'n tydelike diens (byvoorbeeld, "BTOBTO") op die teikenrekenaar te skep om bevele uit te voer via cmd.exe (%COMSPEC%), sonder om enige binêre lêers af te laai.
- Ten spyte van sy sluipende benadering, genereer dit wel gebeurtenislogs vir elke uitgevoerde bevel, wat 'n vorm van nie-interaktiewe "shell" bied.
- Die bevel om te koppel met behulp van **Smbexec** lyk soos dit:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### Uitvoering van Opdragte Sonder Binêre Lêers

- **Smbexec** maak direkte opdraguitvoering deur diens binêre lêer-paaie moontlik, wat die behoefte aan fisiese binêre lêers op die teiken uitskakel.
- Hierdie metode is nuttig vir die uitvoering van eenmalige opdragte op 'n Windows-teiken. Deur dit byvoorbeeld te koppel met Metasploit se `web_delivery`-module, kan 'n PowerShell-gerigte omgekeerde Meterpreter-lading suksesvol uitgevoer word.
- Deur 'n afgeleë diens op die aanvaller se masjien te skep met binPath wat ingestel is om die verskafte opdrag deur cmd.exe uit te voer, is dit moontlik om die lading suksesvol uit te voer, en sodoende terugroep en lading-uitvoering met die Metasploit luisteraar te bereik, selfs as diensresponsfoute voorkom.

### Opdragvoorbeeld

Die skep en begin van die diens kan met die volgende opdragte bereik word:
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
## Verwysings
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
