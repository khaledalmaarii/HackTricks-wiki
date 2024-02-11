# macOS Draadinspuiting via Taakpoort

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Kode

* [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
* [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)


## 1. Draadkaping

Aanvanklik word die **`task_threads()`**-funksie op die taakpoort aangeroep om 'n draadlys van die afgeleë taak te verkry. 'n Draad word gekies om te kap. Hierdie benadering wyk af van konvensionele kode-inspuitingsmetodes, aangesien die skep van 'n nuwe afgeleë draad verbied word as gevolg van die nuwe mitigasie wat `thread_create_running()` blokkeer.

Om die draad te beheer, word **`thread_suspend()`** geroep om sy uitvoering te stuit.

Die enigste toegelate operasies op die afgeleë draad behels die **stop** en **begin** daarvan, die **herwinning** en **verandering** van sy registerwaardes. Afgeleë funksie-oproepe word geïnisieer deur die registers `x0` tot `x7` in te stel op die **argumente**, die **`pc`** te konfigureer om die gewenste funksie te teiken, en die draad te aktiveer. Om te verseker dat die draad nie na die terugkeer afskakel nie, is dit nodig om die terugkeer op te spoor.

Een strategie behels die **registreer van 'n uitsonderingshanterer** vir die afgeleë draad deur `thread_set_exception_ports()` te gebruik, deur die `lr`-register na 'n ongeldige adres voor die funksie-oproep te stel. Dit veroorsaak 'n uitsondering na die funksie-uitvoering, wat 'n boodskap na die uitsonderingspoort stuur en die staat inspekteer om die terugkeerwaarde te herstel. As alternatief, soos aangeneem van Ian Beer se triple\_fetch-exploit, word `lr` ingestel om oneindig te loop. Die draad se register word dan voortdurend gemonitor totdat **`pc` na daardie instruksie wys**.

## 2. Mach-poorte vir kommunikasie

Die volgende fase behels die vestiging van Mach-poorte om kommunikasie met die afgeleë draad te fasiliteer. Hierdie poorte is instrumenteel in die oordrag van willekeurige stuur- en ontvangsregte tussen take.

Vir tweerigtingkommunikasie word twee Mach-ontvangsregte geskep: een in die plaaslike en die ander in die afgeleë taak. Daarna word 'n stuurreg vir elke poort oorgedra na die teenoorgestelde taak, wat boodskapuitruiling moontlik maak.

Met die fokus op die plaaslike poort, word die ontvangsreg deur die plaaslike taak aangehou. Die poort word geskep met `mach_port_allocate()`. Die uitdaging lê daarin om 'n stuurreg na hierdie poort oor te dra na die afgeleë taak.

'n Strategie behels die gebruik van `thread_set_special_port()` om 'n stuurreg na die plaaslike poort in die afgeleë draad se `THREAD_KERNEL_PORT` te plaas. Daarna word die afgeleë draad geïnstrueer om `mach_thread_self()` te roep om die stuurreg te herwin.

Vir die afgeleë poort word die proses in wese omgekeer. Die afgeleë draad word geïnstrueer om 'n Mach-poort te genereer via `mach_reply_port()` (aangesien `mach_port_allocate()` ongeskik is as gevolg van sy terugkeer-meganisme). By die skep van die poort word `mach_port_insert_right()` in die afgeleë draad geroep om 'n stuurreg te vestig. Hierdie reg word dan in die kernel gestoor deur `thread_set_special_port()` te gebruik. Terug in die plaaslike taak word `thread_get_special_port()` gebruik op die afgeleë draad om 'n stuurreg te bekom na die nuut toegewese Mach-poort in die afgeleë taak.

Voltooiing van hierdie stappe lei tot die vestiging van Mach-poorte, wat die grondslag lê vir tweerigtingkommunikasie.

## 3. Basiese Geheue Lees-/Skryfprimitiewe

In hierdie gedeelte lê die fokus op die gebruik van die uitvoerprimitief om basiese geheue lees- en skryfprimitiewe te vestig. Hierdie aanvanklike stappe is noodsaaklik om meer beheer oor die afgeleë proses te verkry, alhoewel die primitiewe op hierdie stadium nie baie doeleindes dien nie. Binnekort sal hulle opgradeer word na meer gevorderde weergawes.

### Geheue lees en skryf met behulp van die uitvoerprimitief

Die doel is om geheue lees en skryf uit te voer met behulp van spesifieke funksies. Vir geheue lees word funksies met die volgende struktuur gebruik:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
En vir skryf na geheue, word funksies soortgelyk aan hierdie struktuur gebruik:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Hierdie funksies stem ooreen met die gegewe saamgestelde instruksies:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Identifiseer Geskikte Funksies

'n Skandering van algemene biblioteke het geskikte kandidate vir hierdie operasies geïdentifiseer:

1. **Lees van Geheue:**
Die `property_getName()`-funksie van die [Objective-C runtime-biblioteek](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html) word geïdentifiseer as 'n geskikte funksie vir die lees van geheue. Die funksie word hieronder uiteengesit:
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
Hierdie funksie tree effektief op soos die `read_func` deur die eerste veld van `objc_property_t` terug te gee.

2. **Skryf van Geheue:**
Dit is meer uitdagend om 'n voorafgeboude funksie vir die skryf van geheue te vind. Die `_xpc_int64_set_value()` funksie van libxpc is egter 'n geskikte kandidaat met die volgende disassemblage:
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Om 'n 64-bit skryf by 'n spesifieke adres uit te voer, word die afstandsoproep gestruktureer as:
```c
_xpc_int64_set_value(address - 0x18, value)
```
Met hierdie primitiewe gevestig, is die verhoog gestel vir die skep van gedeelde geheue, wat 'n beduidende vordering in die beheer van die afgeleë proses beteken.

## 4. Gedeelde Geheue Opstelling

Die doel is om gedeelde geheue tussen plaaslike en afgeleë take te vestig, wat data-oordrag vereenvoudig en die aanroep van funksies met veelvuldige argumente fasiliteer. Die benadering behels die benutting van `libxpc` en sy `OS_xpc_shmem` objek tipe, wat gebaseer is op Mach-geheueinskrywings.

### Prosessoorsig:

1. **Geheue-toekenning**:
- Ken die geheue toe vir deling deur `mach_vm_allocate()` te gebruik.
- Gebruik `xpc_shmem_create()` om 'n `OS_xpc_shmem` objek vir die toegewese geheuegebied te skep. Hierdie funksie sal die skepping van die Mach-geheueinskrywing bestuur en die Mach-stuurreg op offset `0x18` van die `OS_xpc_shmem` objek stoor.

2. **Skep van Gedeelde Geheue in Afgeleë Proses**:
- Ken geheue toe vir die `OS_xpc_shmem` objek in die afgeleë proses met 'n afgeleë oproep na `malloc()`.
- Kopieer die inhoud van die plaaslike `OS_xpc_shmem` objek na die afgeleë proses. Hierdie aanvanklike kopie sal egter verkeerde Mach-geheueinskrywingname hê by offset `0x18`.

3. **Korrigeer die Mach-Geheueinskrywing**:
- Maak gebruik van die `thread_set_special_port()` metode om 'n stuurreg vir die Mach-geheueinskrywing in die afgeleë taak in te voeg.
- Korrekteer die Mach-geheueinskrywingveld by offset `0x18` deur dit te oorskryf met die naam van die afgeleë geheueinskrywing.

4. **Voltooiing van Gedeelde Geheue Opstelling**:
- Valideer die afgeleë `OS_xpc_shmem` objek.
- Stel die gedeelde geheueafbeelding op met 'n afgeleë oproep na `xpc_shmem_remote()`.

Deur hierdie stappe te volg, sal gedeelde geheue tussen die plaaslike en afgeleë take doeltreffend opgestel word, wat eenvoudige data-oordrag en die uitvoering van funksies met veelvuldige argumente moontlik maak.

## Addisionele Kodefragmente

Vir geheue-toekenning en die skep van gedeelde geheue objekte:
```c
mach_vm_allocate();
xpc_shmem_create();
```
Vir die skep en regstelling van die gedeelde geheue-object in die afgeleë proses:
```c
malloc(); // for allocating memory remotely
thread_set_special_port(); // for inserting send right
```
Onthou om die besonderhede van Mach-poorte en geheue-invoernaam korrek te hanteer om te verseker dat die gedeelde geheue korrek funksioneer.

## 5. Volledige beheer bereik

Nadat ons suksesvol gedeelde geheue opgestel en willekeurige uitvoeringsvermoëns verkry het, het ons in wese volledige beheer oor die teikenproses verkry. Die sleutelfunksies wat hierdie beheer moontlik maak, is:

1. **Willekeurige Geheue-operasies**:
- Voer willekeurige geheuelesings uit deur `memcpy()` aan te roep om data van die gedeelde gebied te kopieer.
- Voer willekeurige geheue-skrywings uit deur `memcpy()` te gebruik om data na die gedeelde gebied oor te dra.

2. **Hantering van Funksie-oproepe met Meerdere Argumente**:
- Vir funksies wat meer as 8 argumente vereis, reël die bykomende argumente op die stapel in ooreenstemming met die oproepkonvensie.

3. **Mach-poortoorplasing**:
- Oordra van Mach-poorte tussen take deur Mach-boodskappe via voorheen opgestelde poorte.

4. **Lêerbeskryweroorplasing**:
- Oordra van lêerbeskrywers tussen prosesse deur gebruik te maak van lêerpoorte, 'n tegniek wat deur Ian Beer in `triple_fetch` beklemtoon word.

Hierdie omvattende beheer word gekapsuleer binne die [threadexec](https://github.com/bazad/threadexec) biblioteek, wat 'n gedetailleerde implementering en 'n gebruikersvriendelike API bied vir interaksie met die slagofferproses.

## Belangrike oorwegings:

- Verseker korrekte gebruik van `memcpy()` vir geheuelees-/skryfoperasies om die stabiliteit van die stelsel en die integriteit van data te handhaaf.
- Wanneer Mach-poorte of lêerbeskrywers oorgedra word, volg korrekte protokolle en hanteer hulpbronne verantwoordelik om lekke of onbedoelde toegang te voorkom.

Deur hierdie riglyne na te kom en die `threadexec` biblioteek te gebruik, kan 'n persoon prosesse doeltreffend bestuur en interaksie daarmee op 'n fynvlakvlak bereik, en sodoende volledige beheer oor die teikenproses verkry.

## Verwysings
* [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
