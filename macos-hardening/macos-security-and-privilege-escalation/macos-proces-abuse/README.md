# macOS Proseshandelinge

{% hint style="success" %}
Leer & oefen AWS-hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP-hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}

## Basiese Inligting oor Prosesse

'n Proses is 'n instansie van 'n lopende uitvoerbare lêer, maar prosesse voer nie kode uit nie, dit is drade. Daarom **is prosesse net houers vir lopende drade** wat die geheue, beskrywers, poorte, toestemmings voorsien...

Tradisioneel is prosesse binne ander prosesse (behalwe PID 1) begin deur **`fork`** te roep wat 'n presiese kopie van die huidige proses sou skep en dan sou die **kindproses** gewoonlik **`execve`** roep om die nuwe uitvoerbare lêer te laai en dit uit te voer. Toe is **`vfork`** ingevoer om hierdie proses vinniger te maak sonder enige geheuekopie.\
Toe is **`posix_spawn`** ingevoer wat **`vfork`** en **`execve`** in een oproep kombineer en vlae aanvaar:

* `POSIX_SPAWN_RESETIDS`: Stel effektiewe ids terug na regte ids
* `POSIX_SPAWN_SETPGROUP`: Stel prosesgroepaffiliasie in
* `POSUX_SPAWN_SETSIGDEF`: Stel seinstandaardgedrag in
* `POSIX_SPAWN_SETSIGMASK`: Stel seinmasker in
* `POSIX_SPAWN_SETEXEC`: Voer in dieselfde proses uit (soos `execve` met meer opsies)
* `POSIX_SPAWN_START_SUSPENDED`: Begin opgeskort
* `_POSIX_SPAWN_DISABLE_ASLR`: Begin sonder ASLR
* `_POSIX_SPAWN_NANO_ALLOCATOR:` Gebruik libmalloc se Nano-toewysers
* `_POSIX_SPAWN_ALLOW_DATA_EXEC:` Laat `rwx` toe op data-segmente
* `POSIX_SPAWN_CLOEXEC_DEFAULT`: Sluit alle lêerbeskrywings op exec(2) standaard
* `_POSIX_SPAWN_HIGH_BITS_ASLR:` Randomiseer hoë bietjies van ASLR skuif

Verder laat `posix_spawn` toe om 'n reeks van **`posix_spawnattr`** te spesifiseer wat sekere aspekte van die geskepte proses beheer, en **`posix_spawn_file_actions`** om die toestand van die beskrywers te wysig.

Wanneer 'n proses sterf, stuur dit die **terugvoerkode na die ouerproses** (as die ouer sterf, is die nuwe ouer PID 1) met die sein `SIGCHLD`. Die ouer moet hierdie waarde kry deur `wait4()` of `waitid()` te roep en totdat dit gebeur bly die kind in 'n zombie-toestand waar dit nog gelys word maar nie hulpbronne verbruik nie.

### PIDs

PIDs, prosesidentifiseerders, identifiseer 'n unieke proses. In XNU is die **PIDs** van **64-bits** wat monotonies toeneem en **nooit oorvloei** (om misbruik te voorkom).

### Prosesgroepe, Sessies & Coalisies

**Prosesse** kan in **groepe** geplaas word om dit makliker te maak om hulle te hanteer. Byvoorbeeld, opdragte in 'n skulpskrip sal in dieselfde prosesgroep wees sodat dit moontlik is om hulle saam te **seineer** deur byvoorbeeld te doodmaak.\
Dit is ook moontlik om **prosesse in sessies** te groepeer. Wanneer 'n proses 'n sessie begin (`setsid(2)`), word die kinderprosesse binne die sessie geplaas, tensy hulle hul eie sessie begin.

Coalition is 'n ander manier om prosesse in Darwin te groepeer. 'n Proses wat by 'n coalisie aansluit, kan toegang verkry tot poelhulpbronne, 'n grootboek deel of Jetsam in die gesig staar. Coalisies het verskillende rolle: Leier, XPC-diens, Uitbreiding.

### Gelde & Persone

Elke proses hou **gelde** aan wat **sy voorregte identifiseer** in die stelsel. Elke proses sal een primêre `uid` en een primêre `gid` hê (alhoewel dit dalk tot verskeie groepe behoort).\
Dit is ook moontlik om die gebruiker- en groep-id te verander as die binêre lêer die `setuid/setgid`-bietjie het.\
Daar is verskeie funksies om **nuwe uids/gids** in te stel.

Die systaalaanroep **`persona`** bied 'n **alternatiewe** stel **gelde** aan. Die aanneem van 'n persona aanvaar sy uid, gid en groepslidmaatskappe **op een keer**. In die [**bronkode**](https://github.com/apple/darwin-xnu/blob/main/bsd/sys/persona.h) is dit moontlik om die struktuur te vind:
```c
struct kpersona_info { uint32_t persona_info_version;
uid_t    persona_id; /* overlaps with UID */
int      persona_type;
gid_t    persona_gid;
uint32_t persona_ngroups;
gid_t    persona_groups[NGROUPS];
uid_t    persona_gmuid;
char     persona_name[MAXLOGNAME + 1];

/* TODO: MAC policies?! */
}
```
## Drade Basiese Inligting

1. **POSIX Drade (pthreads):** macOS ondersteun POSIX drade (`pthreads`), wat deel is van 'n standaard drade API vir C/C++. Die implementering van pthreads in macOS word gevind in `/usr/lib/system/libsystem_pthread.dylib`, wat afkomstig is van die openbarelik beskikbare `libpthread`-projek. Hierdie biblioteek voorsien die nodige funksies om drade te skep en te bestuur.
2. **Skep Drade:** Die `pthread_create()`-funksie word gebruik om nuwe drade te skep. Intern, roep hierdie funksie `bsdthread_create()` aan, wat 'n laervlak-sisteemaanroep is wat spesifiek is vir die XNU-kernel (die kernel waarop macOS gebaseer is). Hierdie sisteemaanroep neem verskeie vlae afgelei van `pthread_attr` (eienskappe) wat drade se gedrag spesifiseer, insluitend skeduleringsbeleide en stokgrootte.
* **Verstek Stokgrootte:** Die verstek stokgrootte vir nuwe drade is 512 KB, wat voldoende is vir tipiese werksaamhede, maar aangepas kan word via draadseienskappe as meer of minder spasie benodig word.
3. **Draadinisialisering:** Die `__pthread_init()`-funksie is noodsaaklik tydens draadopstelling, waar die `env[]`-argument gebruik word om omgewingsveranderlikes te ontled wat besonderhede oor die stok se ligging en grootte kan insluit.

#### Draad Beëindiging in macOS

1. **Draad Uittree:** Drade word tipies beëindig deur `pthread_exit()` aan te roep. Hierdie funksie laat 'n draad toe om skoon uit te tree, nodige skoonmaakwerk te doen en die draad toe te laat om 'n terugvoerwaarde terug te stuur na enige aansluiters.
2. **Draad Skoonmaak:** Na die aanroep van `pthread_exit()`, word die funksie `pthread_terminate()` geaktiveer, wat die verwydering van alle geassosieerde draadstrukture hanteer. Dit deallokeer Mach-draadpoorte (Mach is die kommunikasiestelsel in die XNU-kernel) en roep `bsdthread_terminate` aan, 'n sisteemaanroep wat die kernelvlakstrukture verwyder wat met die draad geassosieer is.

#### Sinksronisasie Meganismes

Om toegang tot gedeelde bronne te bestuur en wedloopvoorwaardes te vermy, voorsien macOS verskeie sinksronisasieprimitiewe. Hierdie is krities in multi-draad-omgewings om data-integriteit en stelselstabiliteit te verseker:

1. **Mutexes:**
* **Gewone Mutex (Handtekening: 0x4D555458):** Standaard mutex met 'n geheueafdruk van 60 byte (56 byte vir die mutex en 4 byte vir die handtekening).
* **Vinnige Mutex (Handtekening: 0x4d55545A):** Soortgelyk aan 'n gewone mutex, maar geoptimeer vir vinniger werksaamhede, ook 60 byte groot.
2. **Toestandsveranderlikes:**
* Gebruik vir wag vir sekere toestande om voor te kom, met 'n grootte van 44 byte (40 byte plus 'n 4-byte handtekening).
* **Toestandsveranderlike Eienskappe (Handtekening: 0x434e4441):** Konfigurasie-eienskappe vir toestandsveranderlikes, grootte van 12 byte.
3. **Eenkeer Veranderlike (Handtekening: 0x4f4e4345):**
* Verseker dat 'n stuk inisialisasiekode slegs een keer uitgevoer word. Dit is 12 byte groot.
4. **Lees-Skryfslotte:**
* Laat meerdere lesers of een skrywer op 'n slag toe, wat doeltreffende toegang tot gedeelde data fasiliteer.
* **Lees-Skryfslot (Handtekening: 0x52574c4b):** Grootte van 196 byte.
* **Lees-Skryfslot Eienskappe (Handtekening: 0x52574c41):** Eienskappe vir lees-skryfsluite, grootte van 20 byte.

{% hint style="success" %}
Die laaste 4 byte van daardie voorwerpe word gebruik om oorvloei te bepaal.
{% endhint %}

### Draad Plaaslike Veranderlikes (TLV)

**Draad Plaaslike Veranderlikes (TLV)** in die konteks van Mach-O-lêers (die formaat vir uitvoerbare lêers in macOS) word gebruik om veranderlikes te verklaar wat spesifiek is vir **elke draad** in 'n multi-draad-toepassing. Dit verseker dat elke draad sy eie aparte instansie van 'n veranderlike het, wat 'n manier bied om konflikte te vermy en data-integriteit te handhaaf sonder om eksplisiete sinksronisasie-meganismes soos mutexes nodig te hê.

In C en verwante tale kan jy 'n draad-plaaslike veranderlike verklaar deur die **`__thread`** sleutelwoord te gebruik. Hier is hoe dit werk in jou voorbeeld:
```c
cCopy code__thread int tlv_var;

void main (int argc, char **argv){
tlv_var = 10;
}
```
Hierdie snipper definieer `tlv_var` as 'n draad-plaaslike veranderlike. Elke draad wat hierdie kode hardloop, sal sy eie `tlv_var` hê, en veranderinge wat een draad aan `tlv_var` maak, sal nie `tlv_var` in 'n ander draad beïnvloed nie.

In die Mach-O binêre lêer is die data wat verband hou met draad-plaaslike veranderlikes georganiseer in spesifieke seksies:

* **`__DATA.__thread_vars`**: Hierdie seksie bevat die metadata oor die draad-plaaslike veranderlikes, soos hul tipes en inisialisasiestatus.
* **`__DATA.__thread_bss`**: Hierdie seksie word gebruik vir draad-plaaslike veranderlikes wat nie eksplisiet geïnisialiseer is nie. Dit is 'n deel van die geheue wat apart gesit word vir nul-geïnisialiseerde data.

Mach-O bied ook 'n spesifieke API genaamd **`tlv_atexit`** om draad-plaaslike veranderlikes te bestuur wanneer 'n draad eindig. Hierdie API laat jou toe om **destruktore te registreer**—spesiale funksies wat draad-plaaslike data skoonmaak wanneer 'n draad beëindig.

### Draad Prioriteite

Die begrip van draad prioriteite behels om te kyk na hoe die bedryfstelsel besluit watter drade om uit te voer en wanneer. Hierdie besluit word beïnvloed deur die prioriteitsvlak wat aan elke draad toegewys is. In macOS en Unix-soortgelyke stelsels word dit hanteer deur konsepte soos `nice`, `renice`, en Kwaliteit van Diens (QoS) klasse.

#### Nice en Renice

1. **Nice:**
* Die `nice` waarde van 'n proses is 'n nommer wat sy prioriteit beïnvloed. Elke proses het 'n nice waarde wat wissel tussen -20 (die hoogste prioriteit) en 19 (die laagste prioriteit). Die verstek nice waarde wanneer 'n proses geskep word, is tipies 0.
* 'n Laer nice waarde (nader aan -20) maak 'n proses meer "selfsugtig," en gee dit meer CPU-tyd in vergelyking met ander prosesse met hoër nice waardes.
2. **Renice:**
* `renice` is 'n bevel wat gebruik word om die nice waarde van 'n reeds lopende proses te verander. Dit kan gebruik word om dinamies die prioriteit van prosesse aan te pas, deur hul CPU-tydtoekenning te verhoog of te verlaag gebaseer op nuwe nice waardes.
* Byvoorbeeld, as 'n proses tydelik meer CPU-hulpbronne benodig, kan jy sy nice waarde verlaag met behulp van `renice`.

#### Kwaliteit van Diens (QoS) Klasse

QoS klasse is 'n meer moderne benadering tot die hanteer van draad prioriteite, veral in stelsels soos macOS wat **Grand Central Dispatch (GCD)** ondersteun. QoS klasse laat ontwikkelaars toe om werk te **kategoriseer** in verskillende vlakke gebaseer op hul belangrikheid of dringendheid. macOS bestuur draad prioritisering outomaties gebaseer op hierdie QoS klasse:

1. **Gebruiker Interaktief:**
* Hierdie klas is vir take wat tans met die gebruiker interaksie het of onmiddellike resultate benodig om 'n goeie gebruikerervaring te bied. Hierdie take kry die hoogste prioriteit om die koppelvlak responsief te hou (bv. animasies of gebeurtenishantering).
2. **Gebruiker Geïnisieer:**
* Take wat die gebruiker inisieer en onmiddellike resultate verwag, soos die oopmaak van 'n dokument of die klik op 'n knoppie wat berekeninge benodig. Hierdie take is hoë prioriteit, maar onder gebruiker interaktief.
3. **Hulpprogram:**
* Hierdie take is langdurig en toon tipies 'n vordering aanwyser (bv. lêers aflaai, data invoer). Hulle is laer in prioriteit as gebruiker-geïnisieerde take en hoef nie onmiddellik klaar te wees nie.
4. **Agtergrond:**
* Hierdie klas is vir take wat in die agtergrond werk en nie sigbaar is vir die gebruiker nie. Dit kan take soos indeksering, sinchronisering, of rugsteun wees. Hulle het die laagste prioriteit en minimale impak op stelselverrigting.

Deur QoS klasse te gebruik, hoef ontwikkelaars nie die presiese prioriteitsgetalle te bestuur nie, maar eerder te fokus op die aard van die taak, en die stelsel optimaliseer die CPU-hulpbronne dienooreenkomstig.

Daarbenewens is daar verskillende **draad skeduleringsbeleide** wat vloei om 'n stel skeduleringsparameters te spesifiseer wat die skeduler in ag sal neem. Dit kan gedoen word met behulp van `thread_policy_[set/get]`. Dit kan nuttig wees in wedloopvoorwaarde aanvalle.

## MacOS Proseshandeling

MacOS, soos enige ander bedryfstelsel, bied 'n verskeidenheid metodes en meganismes vir **prosesse om te interaksieer, kommunikeer, en data te deel**. Terwyl hierdie tegnieke noodsaaklik is vir doeltreffende stelselwerking, kan dit ook misbruik word deur bedreigingsakteurs om **booswillige aktiwiteite uit te voer**.

### Biblioteekinspuiting

Biblioteekinspuiting is 'n tegniek waarin 'n aanvaller **'n proses dwing om 'n booswillige biblioteek te laai**. Sodra ingespuit, hardloop die biblioteek in die konteks van die teikenproses, wat die aanvaller dieselfde toestemmings en toegang gee as die proses.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### Funksiehaak

Funksiehaak behels **die onderskepping van funksie-oproepe** of boodskappe binne 'n sagtewarekode. Deur funksies te haak, kan 'n aanvaller **die gedrag** van 'n proses wysig, sensitiewe data waarneem, of selfs beheer oor die uitvoervloei verkry.

{% content-ref url="macos-function-hooking.md" %}
[macos-function-hooking.md](macos-function-hooking.md)
{% endcontent-ref %}

### Interproseskommunikasie

Interproseskommunikasie (IPC) verwys na verskillende metodes waardeur afsonderlike prosesse **data deel en uitruil**. Terwyl IPC fundamenteel is vir baie wettige toepassings, kan dit ook misbruik word om prosesisolasie te omseil, sensitiewe inligting te lek, of ongemagtigde aksies uit te voer.

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Elektron Toepassingsinspuiting

Elektron-toepassings wat uitgevoer word met spesifieke omgewingsveranderlikes kan vatbaar wees vir prosesinspuiting:

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### Chromium Inspuiting

Dit is moontlik om die vlae `--load-extension` en `--use-fake-ui-for-media-stream` te gebruik om 'n **man in die blaaier aanval** uit te voer wat toelaat om toetsaanslae, verkeer, koekies te steel, skripte in bladsye in te spuit...:

{% content-ref url="macos-chromium-injection.md" %}
[macos-chromium-injection.md](macos-chromium-injection.md)
{% endcontent-ref %}

### Vuil NIB

NIB-lêers **definieer gebruikerskoppelvlak (UI) elemente** en hul interaksies binne 'n toepassing. Tog kan hulle **willekeurige bevele uitvoer** en **Gatekeeper stop nie** 'n reeds uitgevoerde toepassing van uitvoering as 'n **NIB-lêer gewysig** word nie. Daarom kan hulle gebruik word om willekeurige programme willekeurige bevele te laat uitvoer:

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Java Toepassingsinspuiting

Dit is moontlik om sekere Java-vermoëns (soos die **`_JAVA_OPTS`** omgewingsveranderlike) te misbruik om 'n Java-toepassing **willekeurige kode/bevele** te laat uitvoer.

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md](macos-java-apps-injection.md)
{% endcontent-ref %}

### .Net Toepassingsinspuiting

Dit is moontlik om kode in .Net-toepassings in te spuit deur **die .Net aflynfunksionaliteit te misbruik** (nie beskerm deur macOS-beskermings soos harding van uitvoertyd).

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Perl Inspuiting

Kyk na verskillende opsies om 'n Perl-skrip willekeurige kode te laat uitvoer in:

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md](macos-perl-applications-injection.md)
{% endcontent-ref %}

### Ruby Inspuiting

Dit is ook moontlik om Ruby-omgewingsveranderlikes te misbruik om willekeurige skripte willekeurige kode te laat uitvoer:

{% content-ref url="macos-ruby-applications-injection.md" %}
[macos-ruby-applications-injection.md](macos-ruby-applications-injection.md)
{% endcontent-ref %}
### Python Injectering

Indien die omgewingsveranderlike **`PYTHONINSPECT`** ingestel is, sal die python-proses in 'n python-cli val sodra dit klaar is. Dit is ook moontlik om **`PYTHONSTARTUP`** te gebruik om 'n python-skrip aan te dui wat aan die begin van 'n interaktiewe sessie uitgevoer moet word.\
Let egter daarop dat die **`PYTHONSTARTUP`** skrip nie uitgevoer sal word wanneer **`PYTHONINSPECT`** die interaktiewe sessie skep nie.

Ander omgewingsveranderlikes soos **`PYTHONPATH`** en **`PYTHONHOME`** kan ook nuttig wees om 'n python-opdrag arbitrêre kode te laat uitvoer.

Let daarop dat uitvoerbare lêers wat met **`pyinstaller`** saamgestel is, nie hierdie omgewingsveranderlikes sal gebruik nie, selfs as hulle uitgevoer word met 'n ingeslote python.

{% hint style="danger" %}
Oor die algemeen kon ek nie 'n manier vind om python arbitrêre kode te laat uitvoer deur omgewingsveranderlikes te misbruik nie.\
Meeste mense installeer egter pyhton met **Hombrew**, wat pyhton in 'n **skryfbare ligging** vir die verstek-admin-gebruiker sal installeer. Jy kan dit oorneem met iets soos:
```bash
mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
cat > /opt/homebrew/bin/python3 <<EOF
#!/bin/bash
# Extra hijack code
/opt/homebrew/bin/python3.old "$@"
EOF
chmod +x /opt/homebrew/bin/python3
```
Selfs **root** sal hierdie kode hardloop wanneer python uitgevoer word.
{% endhint %}

## Opmerking

### Skild

[**Skild**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) is 'n oopbron toepassing wat **proses inspuiting kan opspoor en blokkeer**:

* Deur **Omgewingsveranderlikes** te gebruik: Dit sal die teenwoordigheid van enige van die volgende omgewingsveranderlikes monitor: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** en **`ELECTRON_RUN_AS_NODE`**
* Deur **`task_for_pid`** oproepe te gebruik: Om te vind wanneer een proses die **taakpoort van 'n ander** wil kry wat dit moontlik maak om kode in die proses in te spuit.
* **Electron apps parameters**: Iemand kan **`--inspect`**, **`--inspect-brk`** en **`--remote-debugging-port`** bevellyn argument gebruik om 'n Electron app in afstemmingsmodus te begin, en sodoende kode daarin in te spuit.
* Deur **symboliese skakels** of **harde skakels** te gebruik: Tipies is die mees algemene misbruik om 'n skakel met ons gebruikersbevoegdhede te **plaas**, en dit na 'n hoër bevoorregte ligging te **rig**. Die opsporing is baie eenvoudig vir beide harde skakels en simboliese skakels. As die proses wat die skakel skep 'n **verskillende bevoorregtingsvlak** as die teikenlêer het, skep ons 'n **waarskuwing**. Ongelukkig is blokkering in die geval van simboliese skakels nie moontlik nie, aangesien ons nie vooraf inligting oor die bestemming van die skakel het nie. Dit is 'n beperking van Apple se EndpointSecuriy-raamwerk.

### Oproepe gemaak deur ander prosesse

In [**hierdie blogpos**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) kan jy vind hoe dit moontlik is om die funksie **`task_name_for_pid`** te gebruik om inligting oor ander **prosesse wat kode in 'n proses inspuit** te kry en dan inligting oor daardie ander proses te kry.

Let daarop dat om daardie funksie te roep, moet jy **dieselfde uid** as die een wat die proses hardloop of **root** wees (en dit gee inligting oor die proses, nie 'n manier om kode in te spuit).

## Verwysings

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

{% hint style="success" %}
Leer & oefen AWS Hack: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}
