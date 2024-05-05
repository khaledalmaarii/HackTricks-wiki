# Die Modbus-Protokol

## Inleiding tot die Modbus-Protokol

Die Modbus-protokol is 'n wyd gebruikte protokol in Industriële Outomatisering en Beheerstelsels. Modbus maak kommunikasie moontlik tussen verskeie toestelle soos programmeerbare logika-beheerders (PLC's), sensors, aktuators, en ander industriële toestelle. Die begrip van die Modbus-protokol is noodsaaklik aangesien dit die mees gebruikte kommunikasieprotokol in die ICS is en 'n groot potensiële aanvalsoppervlak vir snuif en selfs inspuiting van bevele in PLC's het.

Hier word konsepte puntsgewys gestel wat konteks van die protokol en sy aard van werking bied. Die grootste uitdaging in ICS-stelselsekuriteit is die koste van implementering en opgradering. Hierdie protokolle en standaarde is in die vroeë 80's en 90's ontwerp en word steeds wyd gebruik. Aangesien 'n bedryf baie toestelle en verbindinge het, is dit baie moeilik om toestelle op te gradeer, wat hackers 'n voordeel bied om met verouderde protokolle te werk. Aanvalle op Modbus is soos prakties onvermydelik aangesien dit sonder opgradering gebruik gaan word en sy werking krities vir die bedryf is.

## Die Klient-Bedienaar-argitektuur

Modbus-protokol word tipies gebruik as in Klient-Bedienaar-argitektuur waar 'n meester-toestel (klient) kommunikasie met een of meer slawe-toestelle (bedieners) inisieer. Dit word ook verwys as Meester-Slaaf-argitektuur, wat wyd gebruik word in elektronika en IoT met SPI, I2C, ens.

## Seriële en Ethernet-weergawes

Modbus-protokol is ontwerp vir beide, Seriële Kommunikasie sowel as Ethernet Kommunikasie. Die Seriële Kommunikasie word wyd gebruik in erfenisstelsels terwyl moderne toestelle Ethernet ondersteun wat hoë datakoerse bied en meer geskik is vir moderne industriële netwerke.

## Data Voorstelling

Data word in die Modbus-protokol oorgedra as ASCII of Binêr, alhoewel die binêre formaat gebruik word weens sy verenigbaarheid met ouer toestelle.

## Funksiekodes

ModBus-protokol werk met die oordrag van spesifieke funksiekodes wat gebruik word om die PLC's en verskeie beheertoestelle te bedryf. Hierdie gedeelte is belangrik om te verstaan aangesien herhaalaanvalle gedoen kan word deur funksiekodes te heruitsend. Erfenis-toestelle ondersteun geen enkele versleuteling na data-oordrag nie en het gewoonlik lang drade wat hulle verbind, wat lei tot manipulasie van hierdie drade en vaslegging/inspuiting van data.

## Adressering van Modbus

Elke toestel in die netwerk het 'n unieke adres wat noodsaaklik is vir kommunikasie tussen toestelle. Protokolle soos Modbus RTU, Modbus TCP, ens. word gebruik om adressering te implementeer en dien as 'n vervoerlaag vir die data-oordrag. Die data wat oorgedra word, is in die Modbus-protokolformaat wat die boodskap bevat.

Verder implementeer Modbus ook foutkontroles om die integriteit van die oorgedraaide data te verseker. Maar meeste van alles is Modbus 'n Oop Standaard en enigiemand kan dit in hul toestelle implementeer. Dit het hierdie protokol gemaak om 'n globale standaard te word en dit is wydverspreid in die industriële outomatiseringsbedryf.

Dankzij sy grootskaalse gebruik en gebrek aan opgraderings, bied die aanval op Modbus 'n beduidende voordeel met sy aanvalsoppervlak. ICS is hoogs afhanklik van kommunikasie tussen toestelle en enige aanvalle wat op hulle uitgevoer word, kan gevaarlik wees vir die werking van die industriële stelsels. Aanvalle soos herhaling, data-inspuiting, data-snuif en lek, Diensweier, data-vervalsing, ens. kan uitgevoer word as die medium van oordrag deur die aanvaller geïdentifiseer word.
