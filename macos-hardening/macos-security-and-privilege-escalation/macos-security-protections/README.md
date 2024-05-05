# Zaštita macOS sistema

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Gatekeeper

Gatekeeper se obično koristi za referisanje na kombinaciju **Karantina + Gatekeeper + XProtect**, 3 macOS sigurnosna modula koji će pokušati da **spreče korisnike da izvrše potencijalno zlonamerni softver koji su preuzeli**.

Više informacija u:

{% content-ref url="macos-gatekeeper.md" %}
[macos-gatekeeper.md](macos-gatekeeper.md)
{% endcontent-ref %}

## Ograničenja procesa

### SIP - Sistem Integritetske Zaštite

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Pesak

macOS Pesak **ograničava aplikacije** koje se izvršavaju unutar peska na **dozvoljene akcije navedene u profilu Peska** sa kojim aplikacija radi. Ovo pomaže da se osigura da **aplikacija pristupa samo očekivanim resursima**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - **Transparentnost, Saglasnost i Kontrola**

**TCC (Transparentnost, Saglasnost i Kontrola)** je sigurnosni okvir. Namenski je dizajniran da **upravlja dozvolama** aplikacija, posebno regulišući njihov pristup osetljivim funkcijama. To uključuje elemente poput **usluga lokacije, kontakata, fotografija, mikrofona, kamere, pristupačnosti i pristupa celom disku**. TCC osigurava da aplikacije mogu pristupiti ovim funkcijama samo nakon dobijanja eksplicitne saglasnosti korisnika, čime se jača privatnost i kontrola nad ličnim podacima.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

### Ograničenja Pokretanja/Okruženja i Keš Poverenja

Ograničenja pokretanja u macOS-u su sigurnosna funkcija za **regulisanje pokretanja procesa** definisanjem **ko može pokrenuti** proces, **kako** i **odakle**. Uvedena u macOS Ventura, kategorizuju sistemski binarni fajlovi u kategorije ograničenja unutar **keša poverenja**. Svaki izvršni binarni fajl ima postavljena **pravila** za njegovo **pokretanje**, uključujući **sopstvena**, **roditeljska** i **odgovorna** ograničenja. Proširena na aplikacije trećih strana kao **Ograničenja Okruženja** u macOS Sonoma, ove funkcije pomažu u ublažavanju potencijalnih eksploatacija sistema regulisanjem uslova pokretanja procesa.

{% content-ref url="macos-launch-environment-constraints.md" %}
[macos-launch-environment-constraints.md](macos-launch-environment-constraints.md)
{% endcontent-ref %}

## MRT - Alat za Uklanjanje Malvera

Alat za uklanjanje malvera (MRT) je još jedan deo sigurnosne infrastrukture macOS-a. Kao što naziv sugeriše, glavna funkcija MRT-a je da **ukloni poznati malver sa zaraženih sistema**.

Kada se malver otkrije na Mac-u (bilo od strane XProtect-a ili na neki drugi način), MRT se može koristiti za automatsko **uklanjanje malvera**. MRT radi tiho u pozadini i obično se pokreće kada se sistem ažurira ili kada se preuzme nova definicija malvera (izgleda da su pravila koja MRT koristi za otkrivanje malvera unutar binarnog fajla).

Iako su i XProtect i MRT deo sigurnosnih mera macOS-a, obavljaju različite funkcije:

* **XProtect** je preventivni alat. **Proverava fajlove prilikom preuzimanja** (putem određenih aplikacija), i ako otkrije bilo koje poznate vrste malvera, **sprečava otvaranje fajla**, čime sprečava malver da inficira sistem u prvom redu.
* **MRT**, s druge strane, je **reaktivni alat**. Radi nakon što je malver otkriven na sistemu, sa ciljem uklanjanja štetnog softvera radi čišćenja sistema.

Aplikacija MRT se nalazi u **`/Library/Apple/System/Library/CoreServices/MRT.app`**

## Upravljanje Zadacima u Pozadini

**macOS** sada **upozorava** svaki put kada alat koristi dobro poznatu **tehniku za trajno izvršavanje koda** (kao što su Stavke za prijavljivanje, Demoni...), tako da korisnik bolje zna **koji softver se održava**.

<figure><img src="../../../.gitbook/assets/image (1183).png" alt=""><figcaption></figcaption></figure>

Ovo se izvršava sa **demonom** smeštenim u `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` i **agentom** u `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app`

Način na koji **`backgroundtaskmanagementd`** zna da je nešto instalirano u trajnom folderu je putem **dobijanja FSEvents** i kreiranja nekih **rukovatelja** za njih.

Osim toga, postoji plist fajl koji sadrži **dobro poznate aplikacije** koje često ostaju održavane od strane Apple-a smeštene u: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### Enumeracija

Moguće je **enumerisati sve** konfigurisane pozadinske stavke pokretanjem Apple CLI alata:
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
Osim toga, moguće je i prikazati ove informacije pomoću [**DumpBTM**](https://github.com/objective-see/DumpBTM).
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
Ove informacije se čuvaju u **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** i Terminalu je potreban FDA.

### Igranje sa BTM

Kada se pronađe nova postojanost, događa se događaj tipa **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`**. Dakle, bilo koji način da se **spreči** slanje ovog **događaja** ili da se **agent obavesti** korisnika pomoći će napadaču da _**zaobiđe**_ BTM.

* **Resetovanje baze podataka**: Pokretanje sledeće komande će resetovati bazu podataka (trebalo bi je ponovo izgraditi od početka), međutim, iz nekog razloga, nakon pokretanja ove komande, **nijedna nova postojanost neće biti obaveštena dok se sistem ne ponovo pokrene**.
* Potreban je **root**.
```bash
# Reset the database
sfltool resettbtm
```
* **Zaustavite agenta**: Moguće je poslati signal za zaustavljanje agentu kako se **ne bi obaveštavao korisnik** kada se pronađu nove detekcije.
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
* **Greška**: Ako **proces koji je stvorio upornost brzo prestane da postoji nakon toga**, demon će pokušati da **dobije informacije** o tome, **neće uspeti**, i **neće moći da pošalje događaj** koji ukazuje da se nešto novo upornošću.

Reference i **više informacija o BTM**:

* [https://youtu.be/9hjUmT031tc?t=26481](https://youtu.be/9hjUmT031tc?t=26481)
* [https://www.patreon.com/posts/new-developer-77420730?l=fr](https://www.patreon.com/posts/new-developer-77420730?l=fr)
* [https://support.apple.com/en-gb/guide/deployment/depdca572563/web](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
