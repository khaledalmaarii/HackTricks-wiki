# Firmware Analysis

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## **Inleiding**

Firmware is essensiële sagteware wat toestelle in staat stel om korrek te werk deur die hardewarekomponente en die sagteware wat gebruikers mee skakel, te bestuur en te fasiliteer. Dit word gestoor in permanente geheue, wat verseker dat die toestel vanaf die oomblik dat dit aangeskakel word, toegang kan verkry tot noodsaaklike instruksies, wat lei tot die lancering van die bedryfstelsel. Die ondersoek en moontlike wysiging van firmware is 'n kritieke stap in die identifisering van sekuriteitskwesbaarhede.

## **Versameling van inligting**

**Versameling van inligting** is 'n kritieke aanvanklike stap om die samestelling van 'n toestel en die tegnologieë wat dit gebruik, te verstaan. Hierdie proses behels die versameling van data oor:

* Die CPU-argitektuur en bedryfstelsel waarop dit loop
* Spesifieke opstartlaaiers
* Hardeware-opstelling en databladsye
* Kodebasis-metriek en bronlokasies
* Eksterne biblioteke en lisensietipes
* Opdateringsgeskiedenis en reguleringssertifikate
* Argitektoniese en vloeidiagramme
* Sekuriteitsassesserings en geïdentifiseerde kwesbaarhede

Vir hierdie doel is **open-source intelligensie (OSINT)**-hulpmiddels van onskatbare waarde, asook die analise van enige beskikbare open-source sagtewarekomponente deur middel van handmatige en outomatiese hersieningsprosesse. Hulpmiddels soos [Coverity Scan](https://scan.coverity.com) en [Semmle’s LGTM](https://lgtm.com/#explore) bied gratis statiese analise wat benut kan word om potensiële kwessies op te spoor.

## **Verkryging van die firmware**

Die verkryging van firmware kan op verskillende maniere benader word, elk met sy eie vlak van kompleksiteit:

* **Direk** van die bron (ontwikkelaars, vervaardigers)
* **Bou** dit volgens die voorsiene instruksies
* **Aflaai** van amptelike ondersteuningswebwerwe
* Gebruik van **Google-dork**-navrae om gehuisvese firmware-lêers te vind
* Direkte toegang tot **wolkstoorplek** met hulpmiddels soos [S3Scanner](https://github.com/sa7mon/S3Scanner)
* Onderskepping van **opdaterings** deur middel van man-in-die-middel-tegnieke
* **Onttrekking** van die toestel deur middel van verbindings soos **UART**, **JTAG**, of **PICit**
* **Sniffing** vir opdateringsversoeke binne toestelkommunikasie
* Identifisering en gebruik van **hardgekoppelde opdaterings-eindpunte**
* **Dumping** vanaf die opstartlaaier of netwerk
* **Verwydering en lees** van die stoorchip, wanneer al die ander pogings misluk, deur gebruik te maak van geskikte hardewarehulpmiddels

## Analise van die firmware

Nou dat jy die firmware het, moet jy inligting daaroor onttrek om te weet hoe om dit te hanteer. Verskillende hulpmiddels wat jy daarvoor kan gebruik:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```

As jy nie veel vind met daardie gereedskap nie, kyk na die **entropie** van die prent met `binwalk -E <bin>`. As die entropie laag is, is dit nie waarskynlik versleutel nie. As die entropie hoog is, is dit waarskynlik versleutel (of op 'n sekere manier saamgedruk).

Verder kan jy hierdie gereedskap gebruik om **lêers wat in die firmware ingebed is**, uit te trek:

{% content-ref url="../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../generic-methodologies-and-resources/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

Of [**binvis.io**](https://binvis.io/#/) ([kode](https://code.google.com/archive/p/binvis/)) om die lêer te ondersoek.

### Kry die Lêersisteem

Met die vorige genoemde gereedskap soos `binwalk -ev <bin>` behoort jy in staat te wees om die **lêersisteem uit te trek**.\
Binwalk sit dit gewoonlik binne 'n **gids met die naam van die lêersisteem**, wat gewoonlik een van die volgende is: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Handmatige Lêersisteem Uittrekking

Soms sal binwalk **nie die sielkundige byte van die lêersisteem in sy handtekeninge hê nie**. In hierdie gevalle, gebruik binwalk om die **verskuiwing van die lêersisteem te vind en die saamgedrukte lêersisteem** uit die binêre lêer te **uitsny** en die lêersisteem handmatig uit te trek volgens sy tipe deur die volgende stappe te volg.

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

* Vir squashfs (soos in die bogenoemde voorbeeld gebruik)

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

Sodra die firmware verkry is, is dit noodsaaklik om dit te ontleed om die struktuur en potensiële kwesbaarhede daarvan te verstaan. Hierdie proses behels die gebruik van verskeie gereedskap om waardevolle data uit die firmware-beeld te analiseer en te onttrek.

### Gereedskap vir Aanvanklike Analise

'n Stel bevele word verskaf vir die aanvanklike ondersoek van die binêre lêer (verwys as `<bin>`). Hierdie bevele help om lêertipes te identifiseer, strings te onttrek, binêre data te analiseer, en die partisie- en lêersisteemdetails te verstaan:

```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```

Om die versleutelingsstatus van die prent te beoordeel, word die **entropie** nagegaan met `binwalk -E <bin>`. Lae entropie dui op 'n gebrek aan versleuteling, terwyl hoë entropie moontlike versleuteling of kompressie aandui.

Vir die onttrekking van **ingebedde lêers**, word gereedskap en hulpbronne soos die dokumentasie van **file-data-carving-recovery-tools** en **binvis.io** vir lêerondersoek aanbeveel.

### Onttrekking van die Lêersisteem

Met behulp van `binwalk -ev <bin>` kan die lêersisteem gewoonlik onttrek word, dikwels na 'n gids wat vernoem is na die lêersisteemtipe (bv. squashfs, ubifs). Wanneer **binwalk** egter nie die lêersisteemtipe herken as gevolg van ontbrekende magiese bytes nie, is handmatige onttrekking nodig. Dit behels die gebruik van `binwalk` om die lêersisteem se offset op te spoor, gevolg deur die `dd`-opdrag om die lêersisteem uit te sny:

```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```

Daarna, afhangende van die lêersisteemtipe (bv. squashfs, cpio, jffs2, ubifs), word verskillende opdragte gebruik om die inhoud handmatig te onttrek.

### Lêersisteemontleding

Met die lêersisteem onttrek, begin die soektog na sekuriteitsgebreke. Aandag word geskenk aan onveilige netwerkdaemons, hardgekoppelde geloofsbriewe, API-eindpunte, opdateringsserverfunksies, ongekompileerde kodes, opstartskripte en gekompileerde binaire lêers vir aflynontleding.

**Belangrike plekke** en **items** om te ondersoek sluit in:

* **etc/shadow** en **etc/passwd** vir gebruikersgeloofsbriewe
* SSL-sertifikate en sleutels in **etc/ssl**
* Konfigurasie- en skripslêers vir potensiële kwesbaarhede
* Ingeslote binaire lêers vir verdere ontleding
* Algemene IoT-toestel-webbedieners en binaire lêers

Verskeie hulpmiddels help om sensitiewe inligting en kwesbaarhede binne die lêersisteem te ontdek:

* [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) en [**Firmwalker**](https://github.com/craigz28/firmwalker) vir soektog na sensitiewe inligting
* [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT\_core) vir omvattende lêersisteemontleding
* [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), en [**EMBA**](https://github.com/e-m-b-a/emba) vir statiese en dinamiese ontleding

### Sekuriteitskontroles op Gekompileerde Binaire Lêers

Beide bronkode en gekompileerde binaire lêers wat in die lêersisteem gevind word, moet ondersoek word vir kwesbaarhede. Hulpmiddels soos **checksec.sh** vir Unix-binaire lêers en **PESecurity** vir Windows-binaire lêers help om onbeskermde binaire lêers te identifiseer wat uitgebuit kan word.

## Emulering van Firmware vir Dinamiese Ontleding

Die proses van emulering van firmware maak **dinamiese ontleding** van óf 'n toestel se werking óf 'n individuele program moontlik. Hierdie benadering kan uitdagings in die vorm van hardeware- of argitektuurafhanklikhede hê, maar die oordra van die hooflêersisteem of spesifieke binaire lêers na 'n toestel met 'n ooreenstemmende argitektuur en endianness, soos 'n Raspberry Pi, of na 'n voorafgeboude virtuele masjien, kan verdere toetsing fasiliteer.

### Emulering van Individuele Binaire Lêers

Vir die ondersoek van enkelprogramme is dit noodsaaklik om die endianness en CPU-argitektuur van die program te identifiseer.

#### Voorbeeld met MIPS-argitektuur

Om 'n MIPS-argitektuur-binaire lêer te emuleer, kan die volgende opdrag gebruik word:

```bash
file ./squashfs-root/bin/busybox
```

En om die nodige emulasiehulpmiddels te installeer:

```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```

Vir MIPS (big-endian) word `qemu-mips` gebruik, en vir little-endian binaêre lêers sal `qemu-mipsel` die keuse wees.

#### ARM-argitektuur-emulasie

Vir ARM-binaêre lêers is die proses soortgelyk, met die gebruik van die `qemu-arm` emulator vir emulasie.

### Volledige Sisteememulasie

Hulpmiddels soos [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), en ander fasiliteer volledige firmware-emulasie, outomatiseer die proses en help met dinamiese analise.

## Dinamiese Analisetegnieke in die Praktyk

Op hierdie stadium word 'n werklike of geëmuleerde toestelomgewing gebruik vir analise. Dit is noodsaaklik om skeltoegang tot die bedryfstelsel en lêersisteem te behou. Emulasie mag nie hardeware-interaksies perfek naboots nie, wat af en toe emulasie-herstarts noodsaaklik maak. Analise moet die lêersisteem hersien, blootgestelde webbladsye en netwerkdienste uitbuit, en bootloader-kwesbaarhede ondersoek. Firmware-integriteitstoetse is krities om potensiële agterdeur-kwesbaarhede te identifiseer.

## Dinamiese Analisetegnieke

Dinamiese analise behels interaksie met 'n proses of binaêre lêer in sy bedryfsomgewing, deur gebruik te maak van hulpmiddels soos gdb-multiarch, Frida en Ghidra om breekpunte te stel en kwesbaarhede te identifiseer deur middel van fuzzing en ander tegnieke.

## Binaêre Uitbuiting en Bewys-van-Konsep

Die ontwikkeling van 'n Bewys-van-Konsep vir geïdentifiseerde kwesbaarhede vereis 'n diepgaande begrip van die teikenargitektuur en programmering in laervlak-tale. Binaêre tydproteksies in ingebedde stelsels is skaars, maar wanneer dit teenwoordig is, mag tegnieke soos Return Oriented Programming (ROP) nodig wees.

## Voorbereide Bedryfstelsels vir Firmware-analise

Bedryfstelsels soos [AttifyOS](https://github.com/adi0x90/attifyos) en [EmbedOS](https://github.com/scriptingxss/EmbedOS) bied vooraf gekonfigureerde omgewings vir firmware-sekuriteitstoetsing, toegerus met nodige hulpmiddels.

## Voorbereide bedryfstelsels vir Firmware-analise

* [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is 'n distro wat bedoel is om jou te help met die uitvoer van sekuriteitsassessering en penetrasietoetsing van Internet of Things (IoT)-toestelle. Dit bespaar baie tyd deur 'n vooraf gekonfigureerde omgewing met al die nodige hulpmiddels te voorsien.
* [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ingebedde sekuriteitstoetsingsbedryfstelsel gebaseer op Ubuntu 18.04 wat vooraf gelaai is met hulpmiddels vir firmware-sekuriteitstoetsing.

## Kwesbare firmware om te oefen

Om te oefen om kwesbaarhede in firmware te ontdek, gebruik die volgende kwesbare firmwareprojekte as 'n beginpunt.

* OWASP IoTGoat
* [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
* The Damn Vulnerable Router Firmware Project
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
* [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

## Opleiding en Sertifisering

* [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks in PDF aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
