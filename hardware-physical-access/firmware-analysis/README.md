# Firmware Analise

{% hint style="success" %}
Leer & oefen AWS Hack:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}

## **Inleiding**

Firmware is noodsaaklike sagteware wat toestelle in staat stel om korrek te werk deur die bestuur en fasilitering van kommunikasie tussen die hardewarekomponente en die sagteware wat gebruikers mee interaksie het. Dit word gestoor in permanente geheue, wat verseker dat die toestel vanaf die oomblik dat dit aangeskakel word, toegang tot noodsaaklike instruksies kan verkry, wat lei tot die aanvang van die bedryfstelsel. Die ondersoek en moontlike wysiging van firmware is 'n kritieke stap om sekuriteitskwessies te identifiseer.

## **Inligting Versameling**

**Inligting Versameling** is 'n kritieke aanvanklike stap om 'n toestel se samestelling en die tegnologieë wat dit gebruik, te verstaan. Hierdie proses behels die insameling van data oor:

* Die CPU-argitektuur en bedryfstelsel waarop dit loop
* Bootloader spesifieke inligting
* Hardeware uitleg en databladsye
* Kodebasis metriek en bronlokasies
* Eksterne biblioteke en lisensietipes
* Opdateringsgeskiedenisse en reguleringsertifisering
* Argitektoniese en vloeidiagramme
* Sekuriteitsassesserings en geïdentifiseerde kwessies

Vir hierdie doel is **open-source intelligensie (OSINT)**-hulpmiddels van onschatbare waarde, asook die analise van enige beskikbare oopbron-sagtewarekomponente deur middel van handmatige en geoutomatiseerde hersieningsprosesse. Hulpmiddels soos [Coverity Scan](https://scan.coverity.com) en [Semmle’s LGTM](https://lgtm.com/#explore) bied gratis statiese analise wat benut kan word om potensiële kwessies te vind.

## **Verkryging van die Firmware**

Die verkryging van firmware kan op verskeie maniere benader word, elk met sy eie vlak van kompleksiteit:

* **Direk** van die bron (ontwikkelaars, vervaardigers)
* Dit **bou** deur die voorsiene instruksies
* **Aflaai** van amptelike ondersteuningswebwerwe
* Gebruik **Google dork**-navrae om gehuisvese firmware-lêers te vind
* Direkte toegang tot **wolkmagazyn** met hulpmiddels soos [S3Scanner](https://github.com/sa7mon/S3Scanner)
* Onderskepping van **opdaterings** deur man-in-die-middel tegnieke
* **Uitpakking** van die toestel deur koppelings soos **UART**, **JTAG**, of **PICit**
* **Sniffing** vir opdateringsversoeke binne toestelkommunikasie
* Identifisering en gebruik van **hardgekoppelde opdaterings-eindpunte**
* **Dumping** vanaf die bootloader of netwerk
* **Verwydering en lees** van die stoorchip, wanneer alles anders faal, deur die gebruik van toepaslike hardewarehulpmiddels

## Analise van die firmware

Nou dat jy **die firmware het**, moet jy inligting daaroor onttrek om te weet hoe om dit te hanteer. Verskillende hulpmiddels wat jy vir dit kan gebruik:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
Indien jy nie veel vind met daardie gereedskap nie, kontroleer die **entropie** van die beeld met `binwalk -E <bin>`, as die entropie laag is, is dit nie waarskynlik versleutel nie. As die entropie hoog is, is dit waarskynlik versleutel (of op een of ander manier saamgedruk).

Verder kan jy hierdie gereedskap gebruik om **lêers wat binne die firmware ingebed is, te onttrek**:

{% content-ref url="../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

Of [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) om die lêer te inspekteer.

### Kry die Lêersisteem

Met die vorige genoemde gereedskap soos `binwalk -ev <bin>` behoort jy in staat te wees om die **lêersisteem te onttrek**.\
Binwalk onttrek dit gewoonlik binne 'n **vouer wat genoem word na die lêersisteem tipe**, wat gewoonlik een van die volgende is: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Handmatige Lêersisteem Uittrekking

Soms sal binwalk **nie die sielkundige byte van die lêersisteem in sy handtekeninge hê nie**. In hierdie gevalle, gebruik binwalk om die **offset van die lêersisteem te vind en die saamgedrukte lêersisteem te kerf** uit die binêre en **handmatig die lêersisteem te onttrek** volgens sy tipe deur die stappe hieronder te volg.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Voer die volgende **dd-opdrag** uit om die Squashfs-lêersisteem uit te snys.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternatiewelik kan die volgende bevel ook uitgevoer word.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

* Vir squashfs (soos in die voorbeeld hierbo)

`$ unsquashfs dir.squashfs`

Lêers sal daarna in die "`squashfs-root`" gids wees.

* CPIO-argief lêers

`$ cpio -ivd --no-absolute-filenames -F <bin>`

* Vir jffs2-lêersisteme

`$ jefferson rootfsfile.jffs2`

* Vir ubifs-lêersisteme met NAND-flits

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`

## Ontleding van Firmware

Sodra die firmware verkry is, is dit noodsaaklik om dit te ontleed om die struktuur en potensiële kwesbaarhede daarvan te verstaan. Hierdie proses behels die gebruik van verskeie gereedskap om waardevolle data uit die firmwarebeeld te ontleed en te onttrek.

### Inisieële Ontledingsgereedskap

'n Stel bevele word voorsien vir die aanvanklike inspeksie van die binêre lêer (verwys as `<bin>`). Hierdie bevele help om lêertipes te identifiseer, strings te onttrek, binêre data te ontleed, en die partisie- en lêersisteembesonderhede te verstaan:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Om die versleutelingstatus van die beeld te assesseer, word die **entropie** nagegaan met `binwalk -E <bin>`. Lae entropie dui op 'n gebrek aan versleuteling, terwyl hoë entropie moontlike versleuteling of kompressie aandui.

Vir die onttrekking van **ingeslote lêers**, word gereedskap en bronne soos die **file-data-carving-recovery-tools** dokumentasie en **binvis.io** vir lêerinspeksie aanbeveel.

### Onttrekking van die Lêersisteem

Deur `binwalk -ev <bin>` te gebruik, kan die lêersisteem gewoonlik onttrek word, dikwels na 'n gids wat genoem is na die lêersisteemtipe (bv., squashfs, ubifs). Wanneer **binwalk** egter nie die lêersisteemtipe herken as gevolg van ontbrekende sielkundige bytjies nie, is handmatige onttrekking nodig. Dit behels die gebruik van `binwalk` om die lêersisteem se afskuif te vind, gevolg deur die `dd`-bevel om die lêersisteem uit te kerf:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
Na afloop, afhangende van die lêersisteemtipe (bv. squashfs, cpio, jffs2, ubifs), word verskillende bevele gebruik om die inhoud handmatig te onttrek.

### Lêersisteemanalise

Met die lêersisteem onttrek, begin die soektog na sekuriteitsgebreke. Aandag word geskenk aan onveilige netwerkdemonne, hardgekoppelde geloofsbriewe, API-eindpunte, opdateringbedienerfunksionaliteite, ongekompileerde kodes, aanvangskripte, en gekompileerde binêre lêers vir aflynontleding.

**Sleutellokasies** en **items** om te ondersoek sluit in:

- **etc/shadow** en **etc/passwd** vir gebruikersgelde
- SSL-sertifikate en sleutels in **etc/ssl**
- Opset- en skriptlêers vir potensiële kwesbaarhede
- Ingeslote binêre lêers vir verdere ontleding
- Gewone IoT-toestel-webbediener en binêre lêers

Verskeie gereedskap help om sensitiewe inligting en kwesbaarhede binne die lêersisteem bloot te lê:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) en [**Firmwalker**](https://github.com/craigz28/firmwalker) vir soektog na sensitiewe inligting
- [**Die Firmwareontledings- en Vergelykingstool (FACT)**](https://github.com/fkie-cad/FACT\_core) vir omvattende firmware-ontleding
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), en [**EMBA**](https://github.com/e-m-b-a/emba) vir statiese en dinamiese ontleding

### Sekuriteitskontroles op Gekompileerde Binêre Lêers

Bronkode en gekompileerde binêre lêers wat in die lêersisteem gevind word, moet ondersoek word vir kwesbaarhede. Gereedskap soos **checksec.sh** vir Unix-binêre lêers en **PESecurity** vir Windows-binêre lêers help om onbeskermde binêre lêers te identifiseer wat uitgebuit kan word.

## Nabootsing van Firmware vir Dinamiese Ontleding

Die proses van die nabootsing van firmware maak **dinamiese ontleding** van óf 'n toestel se werking óf 'n individuele program moontlik. Hierdie benadering kan uitdagings in die vorm van hardeware- of argitektuurafhanklikhede inhou, maar die oordrag van die hooflêersisteem of spesifieke binêre lêers na 'n toestel met 'n ooreenstemmende argitektuur en endianness, soos 'n Raspberry Pi, of na 'n voorafgeboude virtuele masjien, kan verdere toetsing fasiliteer.

### Nabootsing van Individuele Binêre Lêers

Vir die ondersoek van enkelprogramme is dit noodsaaklik om die endianness en CPU-argitektuur van die program te identifiseer.

#### Voorbeeld met MIPS-argitektuur

Om 'n MIPS-argitektuur binêre lêer na te boots, kan die volgende bevel gebruik word:
```bash
file ./squashfs-root/bin/busybox
```
En om die nodige emulasiehulpmiddels te installeer:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
### ARM-argitektuur Emulasie

Vir ARM-binêre lêers is die proses soortgelyk, met die `qemu-arm` emulator wat gebruik word vir emulasie.

### Volledige Sisteem Emulasie

Hulpmiddels soos [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analise Toolkit](https://github.com/attify/firmware-analysis-toolkit), en ander, fasiliteer volledige firmware emulasie, outomatiseer die proses en help met dinamiese analise.

## Dinamiese Analise in Praktyk

Op hierdie stadium word óf 'n werklike óf 'n geëmuleerde toestelomgewing vir analise gebruik. Dit is noodsaaklik om skaal toegang tot die OS en lêersisteem te behou. Emulasie mag nie hardeware-interaksies perfek naboots nie, wat af en toe emulasie herstarts noodsaaklik maak. Analise behoort die lêersisteem te hersien, blootgestelde webbladsye en netwerkdienste te benut, en opstartlaaier kwesbaarhede te ondersoek. Firmware-integriteitstoetse is krities om potensiële agterdeur kwesbaarhede te identifiseer.

## Runtime Analise Tegnieke

Runtime-analise behels interaksie met 'n proses of binêre lêer in sy bedryfsomgewing, deur gebruik te maak van hulpmiddels soos gdb-multiarch, Frida, en Ghidra om breekpunte in te stel en kwesbaarhede deur fuzzing en ander tegnieke te identifiseer.

## Binêre Uitbuiting en Bewys-van-Konsep

Die ontwikkeling van 'n PoC vir geïdentifiseerde kwesbaarhede vereis 'n diepgaande begrip van die teikenargitektuur en programmering in laervlak tale. Binêre runtime-beskerming in ingebedde stelsels is skaars, maar wanneer teenwoordig, mag tegnieke soos Return Oriented Programming (ROP) nodig wees.

## Voorbereide Bedryfstelsels vir Firmware Analise

Bedryfstelsels soos [AttifyOS](https://github.com/adi0x90/attifyos) en [EmbedOS](https://github.com/scriptingxss/EmbedOS) bied vooraf gekonfigureerde omgewings vir firmware-sekuriteitstoetsing, toegerus met nodige hulpmiddels.

## Voorbereide BS'e om Firmware te analiseer

* [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is 'n distro bedoel om jou te help met die uitvoering van sekerheidsevaluering en indringingstoetsing van Internet of Things (IoT) toestelle. Dit bespaar baie tyd deur 'n vooraf gekonfigureerde omgewing met al die nodige hulpmiddels gelaai te voorsien.
* [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ingeslote sekerheidstoetsbedryfstelsel gebaseer op Ubuntu 18.04 voorgelaai met firmware-sekuriteitstoetsingshulpmiddels.

## Kwesbare firmware om te oefen

Om kwesbaarhede in firmware te ontdek, gebruik die volgende kwesbare firmwareprojekte as 'n beginpunt.

* OWASP IoTGoat
* [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
* Die Damn Vulnerable Router Firmware Project
* [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
* Damn Vulnerable ARM Router (DVAR)
* [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
* ARM-X
* [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
* Azeria Labs VM 2.0
* [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
* Damn Vulnerable IoT Device (DVID)
* [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Verwysings

* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
* [Praktiese IoT Hacking: Die Definitiewe Gids tot die Aanval op die Internet van Dinge](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

## Opleiding en Sertifisering

* [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)
