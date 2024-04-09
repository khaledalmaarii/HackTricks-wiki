# Hakovanje hardvera

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJATELJE**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## JTAG

JTAG omogućava izvođenje skeniranja granica. Skeniranje granica analizira određenu kolažu, uključujući ugrađene ćelije za skeniranje granica i registre za svaki pin.

JTAG standard definiše **specifične komande za sprovođenje skeniranja granica**, uključujući sledeće:

* **BYPASS** vam omogućava da testirate određeni čip bez preopterećenja prolaska kroz druge čipove.
* **SAMPLE/PRELOAD** uzima uzorak podataka koji ulaze i izlaze iz uređaja kada je u normalnom režimu rada.
* **EXTEST** postavlja i čita stanja pinova.

Takođe može podržavati i druge komande kao što su:

* **IDCODE** za identifikaciju uređaja
* **INTEST** za interno testiranje uređaja

Možete naići na ove instrukcije kada koristite alat poput JTAGulatora.

### Testni pristupni port

Skeniranje granica uključuje testove četvoropinskih **Test Access Port (TAP)**, opšti port koji pruža **pristup podršci za testiranje JTAG-a** ugrađenu u komponentu. TAP koristi sledećih pet signala:

* Ulaz testnog sata (**TCK**) TCK je **sat** koji definiše koliko često će kontroler TAP-a preduzeti jednu radnju (drugim rečima, preći na sledeće stanje u mašini stanja).
* Ulaz za izbor režima testiranja (**TMS**) TMS kontroliše **konačnu mašinu stanja**. Na svaki otkucaj sata, kontroler JTAG TAP uređaja proverava napon na TMS pinu. Ako je napon ispod određenog praga, signal se smatra niskim i tumači se kao 0, dok ako je napon iznad određenog praga, signal se smatra visokim i tumači se kao 1.
* Ulaz testnih podataka (**TDI**) TDI je pin koji šalje **podatke u čip putem ćelija za skeniranje**. Svaki proizvođač je odgovoran za definisanje protokola komunikacije preko ovog pina, jer JTAG to ne definiše.
* Izlaz testnih podataka (**TDO**) TDO je pin koji šalje **podatke iz čipa**.
* Ulaz za resetovanje testa (**TRST**) Opcioni TRST resetuje konačnu mašinu stanja **na poznato dobro stanje**. Alternativno, ako se TMS drži na 1 tokom pet uzastopnih ciklusa sata, to poziva reset, na isti način kao što bi to uradio TRST pin, zbog čega je TRST opcionalan.

Ponekad ćete moći da pronađete ove pinove označene na PCB-u. U drugim prilikama možda ćete morati da ih **pronađete**.

### Identifikacija JTAG pinova

Najbrži, ali najskuplji način otkrivanja JTAG portova je korišćenjem **JTAGulatora**, uređaja kreiranog specifično za tu svrhu (mada može **takođe otkriti UART pinoutove**).

Ima **24 kanala** na koje možete povezati pinove ploča. Zatim vrši **BF napad** svih mogućih kombinacija slanjem **IDCODE** i **BYPASS** komandi za skeniranje granica. Ako primi odgovor, prikazuje kanal koji odgovara svakom JTAG signalu.

Jeftiniji, ali mnogo sporiji način identifikacije JTAG pinoutova je korišćenjem [**JTAGenum**](https://github.com/cyphunk/JTAGenum/) učitanog na mikrokontroler kompatibilan sa Arduino-om.

Koristeći **JTAGenum**, prvo biste **definisali pinove uređaja za ispitivanje** koje ćete koristiti za enumeraciju. Morali biste se pozvati na dijagram rasporeda pinova uređaja, a zatim povezati ove pinove sa test tačkama na ciljnom uređaju.

**Treći način** identifikacije JTAG pinova je **inspekcijom PCB-a** za jedan od pinoutova. U nekim slučajevima, PCB-ovi mogu povoljno obezbediti **Tag-Connect interfejs**, što je jasan pokazatelj da ploča ima JTAG konektor, takođe. Možete videti kako taj interfejs izgleda na [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Dodatno, inspekcija **listova sa podacima čipsetova na PCB-u** može otkriti dijagrame rasporeda pinova koji ukazuju na JTAG interfejse.

## SDW

SWD je ARM-specifični protokol dizajniran za debagovanje.

SWD interfejs zahteva **dva pina**: bidirekcionalni **SWDIO** signal, koji je ekvivalent JTAG-ovim **TDI i TDO pinovima i sat**, i **SWCLK**, koji je ekvivalent **TCK** u JTAG-u. Mnogi uređaji podržavaju **Serial Wire ili JTAG Debug Port (SWJ-DP)**, kombinovani JTAG i SWD interfejs koji vam omogućava da povežete ili SWD ili JTAG sonda sa ciljem.
