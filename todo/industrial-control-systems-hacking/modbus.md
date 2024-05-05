# Protokol Modbus

## Uvod u Protokol Modbus

Protokol Modbus je široko korišćen protokol u industrijskoj automatizaciji i kontrolnim sistemima. Modbus omogućava komunikaciju između različitih uređaja kao što su programabilni logički kontroleri (PLC), senzori, aktuatori i drugi industrijski uređaji. Razumevanje Protokola Modbus je ključno jer je ovo najčešće korišćeni komunikacioni protokol u ICS-u i ima veliku potencijalnu površinu napada za prisluškivanje čak i ubacivanje komandi u PLC-ove.

Ovde su koncepti navedeni tačkasto pružajući kontekst protokola i njegovu prirodu rada. Najveći izazov u sigurnosti ICS sistema je trošak implementacije i nadogradnje. Ovi protokoli i standardi su dizajnirani krajem 80-ih i 90-ih godina i još uvek se široko koriste. Pošto industrija ima mnogo uređaja i veza, nadogradnja uređaja je veoma teška, što daje hakerima prednost u radu sa zastarelim protokolima. Napadi na Modbus su praktično neizbežni jer će se koristiti bez nadogradnje, a njegovo funkcionisanje je ključno za industriju.

## Arhitektura Klijent-Server

Protokol Modbus se tipično koristi u arhitekturi Klijent-Server gde glavni uređaj (klijent) inicira komunikaciju sa jednim ili više sporednih uređaja (servera). Ovo se takođe naziva arhitektura Master-Slave, koja se široko koristi u elektronici i IoT sa SPI, I2C, itd.

## Serijske i Ethernet Verzije

Protokol Modbus je dizajniran kako za serijsku komunikaciju tako i za Ethernet komunikaciju. Serijska komunikacija se široko koristi u zastarelim sistemima dok moderni uređaji podržavaju Ethernet koji nudi visoke brzine prenosa podataka i više odgovara modernim industrijskim mrežama.

## Prikaz Podataka

Podaci se prenose u Modbus protokolu kao ASCII ili Binarno, iako se binarni format koristi zbog njegove kompatibilnosti sa starijim uređajima.

## Funkcioni Kodovi

ModBus Protokol radi sa prenosom specifičnih funkcionalnih kodova koji se koriste za rad PLC-ova i različitih kontrolnih uređaja. Ovaj deo je važan za razumevanje jer se napadi ponavljanjem mogu izvršiti ponovnim slanjem funkcionalnih kodova. Zastareli uređaji ne podržavaju nikakvo šifrovanje prema prenosu podataka i obično imaju duge žice koje ih povezuju, što dovodi do manipulacije ovim žicama i hvatanja/ubacivanja podataka.

## Adresiranje Modbus-a

Svaki uređaj u mreži ima jedinstvenu adresu koja je ključna za komunikaciju između uređaja. Protokoli poput Modbus RTU, Modbus TCP, itd. se koriste za implementaciju adresiranja i služe kao transportni sloj za prenos podataka. Podaci koji se prenose su u formatu Modbus protokola koji sadrži poruku.

Osim toga, Modbus takođe implementira provere grešaka kako bi se osigurala integritet prenetih podataka. Ali najvažnije, Modbus je Otvoreni Standard i svako može da ga implementira u svoje uređaje. To je učinilo da ovaj protokol postane globalni standard i da se široko koristi u industriji automatizacije.

Zbog velike upotrebe i nedostatka nadogradnji, napadi na Modbus pružaju značajnu prednost sa svojom površinom napada. ICS je visoko zavistan od komunikacije između uređaja i bilo koji napad na njih može biti opasan za rad industrijskih sistema. Napadi poput ponavljanja, ubacivanja podataka, prisluškivanja i curenja podataka, uskraćivanja usluge, falsifikovanja podataka, itd. mogu se izvršiti ako napadač identifikuje medijum prenosa.
