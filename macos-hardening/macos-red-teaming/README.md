# macOS Red Teaming

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Zloupotreba MDM-ova

* JAMF Pro: `jamf checkJSSConnection`
* Kandji

Ako uspete da **kompromitujete administratorske akreditive** kako biste pristupili upravljačkoj platformi, možete **potencijalno kompromitovati sve računare** distribuiranjem malvera na mašinama.

Za red timovanje u macOS okruženjima, veoma je preporučljivo da imate neko razumevanje o tome kako MDM-ovi funkcionišu:

{% content-ref url="macos-mdm/" %}
[macos-mdm](macos-mdm/)
{% endcontent-ref %}

### Korišćenje MDM-a kao C2

MDM će imati dozvolu da instalira, upita ili ukloni profile, instalira aplikacije, kreira lokalne administratorske naloge, postavi lozinku za firmware, promeni FileVault ključ...

Da biste pokrenuli sopstveni MDM, potrebno je da **vaš CSR bude potpisan od strane prodavca** koji možete pokušati da dobijete sa [**https://mdmcert.download/**](https://mdmcert.download/). A da biste pokrenuli sopstveni MDM za Apple uređaje, možete koristiti [**MicroMDM**](https://github.com/micromdm/micromdm).

Međutim, da biste instalirali aplikaciju na prijavljenom uređaju, i dalje vam je potrebno da bude potpisana od strane developerskog naloga... međutim, prilikom prijavljivanja na MDM, **uređaj dodaje SSL sertifikat MDM-a kao pouzdanog CA**, tako da sada možete potpisati bilo šta.

Da biste prijavili uređaj na MDM, trebate instalirati **`mobileconfig`** fajl kao root, koji se može dostaviti putem **pkg** fajla (možete ga kompresovati u zip i kada se preuzme sa Safari-ja, biće dekompresovan).

**Mythic agent Orthrus** koristi ovu tehniku.

### Zloupotreba JAMF PRO-a

JAMF može pokretati **prilagođene skripte** (skripte razvijene od strane sistem administratora), **nativne payload-e** (kreiranje lokalnih naloga, postavljanje EFI lozinke, praćenje fajlova/procesa...) i **MDM** (konfiguracije uređaja, sertifikati uređaja...).

#### JAMF samoprijavljivanje

Idite na stranicu poput `https://<ime-kompanije>.jamfcloud.com/enroll/` da biste videli da li imaju **omogućeno samoprijavljivanje**. Ako imaju, može **zatražiti akreditive za pristup**.

Možete koristiti skriptu [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) da biste izveli napad prskanjem lozinki.

Osim toga, nakon pronalaženja odgovarajućih akreditiva, možete pokušati da napravite brute-force za druge korisnička imena sa sledećim formularom:

![](<../../.gitbook/assets/image (7) (1) (1).png>)

#### JAMF autentifikacija uređaja

<figure><img src="../../.gitbook/assets/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

**`jamf`** binarni fajl sadrži tajnu za otvaranje keša lozinki koja je u vreme otkrića bila **deljena** među svima i bila je: **`jk23ucnq91jfu9aj`**.\
Osim toga, jamf **trajno ostaje** kao **LaunchDaemon** u **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Preuzimanje kontrole nad JAMF uređajem

URL **JSS** (Jamf Software Server) koji će **`jamf`** koristiti nalazi se u **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Ovaj fajl u osnovi sadrži URL:

{% code overflow="wrap" %}
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
{% endcode %}

Dakle, napadač bi mogao da ubaci zlonamerni paket (`pkg`) koji **prepisuje ovaj fajl** prilikom instalacije, postavljajući **URL na Mythic C2 osluškivač preko Typhon agenta**, kako bi mogao da zloupotrebi JAMF kao C2. 

{% code overflow="wrap" %}
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
{% endcode %}

#### JAMF Impersonacija

Da biste **prevarili komunikaciju** između uređaja i JMF-a, potrebno vam je:

* **UUID** uređaja: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
* **JAMF kejčen** sa lokacije: `/Library/Application\ Support/Jamf/JAMF.keychain` koji sadrži sertifikat uređaja

Sa ovim informacijama, **kreirajte virtuelnu mašinu** sa **ukradenim** hardverskim **UUID**-om i sa **onemogućenim SIP-om**, prenesite **JAMF kejčen**, **hukujte** Jamf **agent** i ukradite njegove informacije.

#### Krađa tajni

<figure><img src="../../.gitbook/assets/image (11).png" alt=""><figcaption><p>a</p></figcaption></figure>

Takođe možete pratiti lokaciju `/Library/Application Support/Jamf/tmp/` za **prilagođene skripte** koje administratori mogu želeli da izvrše putem Jamf-a jer se **ovde smeštaju, izvršavaju i uklanjaju**. Ove skripte **mogu sadržati akreditive**.

Međutim, **akreditivi** mogu biti prosleđeni ovim skriptama kao **parametri**, pa biste trebali pratiti `ps aux | grep -i jamf` (čak i bez root pristupa).

Skripta [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) može pratiti dodavanje novih fajlova i nove argumente procesa.

### Udaljeni pristup macOS-u

I takođe o "specijalnim" **mrežnim** **protokolima** za **MacOS**:

{% content-ref url="../macos-security-and-privilege-escalation/macos-protocols.md" %}
[macos-protocols.md](../macos-security-and-privilege-escalation/macos-protocols.md)
{% endcontent-ref %}

## Active Directory

U nekim slučajevima ćete otkriti da je **MacOS računar povezan sa AD-om**. U ovom scenariju trebali biste pokušati **enumerisati** active directory kao što ste navikli. Pronađite **pomoć** na sledećim stranicama:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

{% content-ref url="../../windows-hardening/active-directory-methodology/" %}
[active-directory-methodology](../../windows-hardening/active-directory-methodology/)
{% endcontent-ref %}

{% content-ref url="../../network-services-pentesting/pentesting-kerberos-88/" %}
[pentesting-kerberos-88](../../network-services-pentesting/pentesting-kerberos-88/)
{% endcontent-ref %}

Neki **lokalni MacOS alati** koji vam mogu pomoći su `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Takođe, postoje neki alati pripremljeni za MacOS koji automatski nabrojavaju AD i igraju se sa kerberosom:

* [**Machound**](https://github.com/XMCyber/MacHound): MacHound je proširenje alata za auditanje Bloodhound koje omogućava prikupljanje i unos odnosa Active Directory-ja na MacOS hostovima.
* [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost je Objective-C projekat dizajniran za interakciju sa Heimdal krb5 API-jima na macOS-u. Cilj projekta je omogućiti bolje testiranje sigurnosti oko Kerberosa na macOS uređajima koristeći native API-je bez zahtevanja bilo kojeg drugog okvira ili paketa na cilju.
* [**Orchard**](https://github.com/its-a-feature/Orchard): JavaScript for Automation (JXA) alat za nabrojavanje Active Directory-ja. 

### Informacije o domenu
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Korisnici

Tri vrste korisnika na MacOS-u su:

* **Lokalni korisnici** - Upravljaju se lokalnom OpenDirectory uslugom i nisu na bilo koji način povezani sa Active Directory-jem.
* **Mrežni korisnici** - Privremeni korisnici Active Directory-ja koji zahtevaju vezu sa DC serverom radi autentifikacije.
* **Mobilni korisnici** - Korisnici Active Directory-ja sa lokalnom rezervnom kopijom svojih akreditiva i datoteka.

Lokalne informacije o korisnicima i grupama čuvaju se u fascikli _/var/db/dslocal/nodes/Default._\
Na primer, informacije o korisniku pod imenom _mark_ čuvaju se u _/var/db/dslocal/nodes/Default/users/mark.plist_, a informacije o grupi _admin_ su u _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Pored korišćenja veza HasSession i AdminTo, **MacHound dodaje tri nove veze** u Bloodhound bazu podataka:

* **CanSSH** - entitet koji je dozvoljen da se SSH-uje na host
* **CanVNC** - entitet koji je dozvoljen da se VNC-uje na host
* **CanAE** - entitet koji je dozvoljen da izvršava AppleEvent skripte na hostu
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
Više informacija na [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

## Pristupanje Keychain-u

Keychain verovatno sadrži osetljive informacije koje, ako se pristupi bez generisanja upozorenja, mogu pomoći u napredovanju u vežbi crvenog tima:

{% content-ref url="macos-keychain.md" %}
[macos-keychain.md](macos-keychain.md)
{% endcontent-ref %}

## Spoljni servisi

MacOS crveno timiranje se razlikuje od redovnog Windows crvenog timiranja jer se obično **MacOS integriše sa nekoliko spoljnih platformi direktno**. Uobičajena konfiguracija MacOS-a je pristupanje računaru koristeći **OneLogin sinhronizovane akreditive i pristupanje nekoliko spoljnih servisa** (kao što su github, aws...) putem OneLogin-a.

## Razne tehnike crvenog tima

### Safari

Kada se fajl preuzme u Safariju, ako je "bezbedan" fajl, **automatski će biti otvoren**. Na primer, ako **preuzmete zip**, automatski će biti dekompresovan:

<figure><img src="../../.gitbook/assets/image (12) (3).png" alt=""><figcaption></figcaption></figure>

## Reference

* [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
* [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
* [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
* [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
* [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje trikove hakovanja slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
