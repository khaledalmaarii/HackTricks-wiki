<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>


## Basiese Konsepte

- **Slim Kontrakte** word gedefinieer as programme wat op 'n blokketting uitgevoer word wanneer sekere voorwaardes voldoen word, wat ooreenkomste outomaties sonder tussenpersone uitvoer.
- **Gedentraliseerde Toepassings (dApps)** bou op slim kontrakte, met 'n gebruikersvriendelike voorkant en 'n deursigtige, auditeerbare agterkant.
- **Tokens & Munte** onderskei waar munte as digitale geld dien, terwyl tokens waarde of eienaarskap in spesifieke kontekste verteenwoordig.
- **Hulpmiddel-Tokens** gee toegang tot dienste, en **Sekuriteits-Tokens** dui bateseienaarskap aan.
- **DeFi** staan vir Gedentraliseerde Finansies en bied finansiële dienste sonder sentrale owerhede.
- **DEX** en **DAO's** verwys onderskeidelik na Gedentraliseerde Ruilplatforms en Gedentraliseerde Outonome Organisasies.

## Konsensusmeganismes

Konsensusmeganismes verseker veilige en ooreengekome transaksievalidasies op die blokketting:
- **Bewys van Werk (PoW)** steun op rekenaarvermoë vir transaksieverifikasie.
- **Bewys van Aandeel (PoS)** vereis dat valideerders 'n sekere hoeveelheid tokens besit, wat energieverbruik verminder in vergelyking met PoW.

## Bitcoin Essensies

### Transaksies

Bitcoin-transaksies behels die oordra van fondse tussen adresse. Transaksies word deur digitale handtekeninge gevalideer, wat verseker dat slegs die eienaar van die privaat sleutel oordragte kan inisieer.

#### Sleutelkomponente:

- **Multisignature-transaksies** vereis meervoudige handtekeninge om 'n transaksie te magtig.
- Transaksies bestaan uit **inskrywings** (bron van fondse), **uitsette** (bestemming), **fooie** (betaal aan myners) en **skripsies** (transaksiereëls).

### Lightning-netwerk

Beoog om die skaalbaarheid van Bitcoin te verbeter deur meervoudige transaksies binne 'n kanaal toe te laat, en slegs die finale toestand na die blokketting uit te saai.

## Bitcoin-privasiemetodes

Privasiemetodes, soos **Gemeenskaplike Invoereienaarskap** en **UTXO-veranderingsadresopsporing**, maak gebruik van transaksiepatrone. Strategieë soos **Mengers** en **CoinJoin** verbeter anonimiteit deur transaksieskakels tussen gebruikers te verdoesel.

## Anonieme verkryging van Bitcoins

Metodes sluit kontanttransaksies, mynbou en die gebruik van mengers in. **CoinJoin** meng verskeie transaksies om spoorbaarheid te bemoeilik, terwyl **PayJoin** CoinJoins as gewone transaksies vermom vir verhoogde privaatheid.


# Bitcoin-privasiemetodes

# Opsomming van Bitcoin-privasiemetodes

In die wêreld van Bitcoin is die privaatheid van transaksies en die anonimiteit van gebruikers dikwels onderwerp van kommer. Hier is 'n vereenvoudigde oorsig van verskeie algemene metodes waarmee aanvallers Bitcoin-privasie kan benadeel.

## **Gemeenskaplike Invoereienaarskap-aanname**

Dit is oor die algemeen selde dat invoere van verskillende gebruikers in 'n enkele transaksie gekombineer word as gevolg van die betrokkenheid van kompleksiteit. Dus word **twee invoeradresse in dieselfde transaksie dikwels aan dieselfde eienaar toegeskryf**.

## **UTXO-veranderingsadresopsporing**

'n UTXO, of **Ongebruikte Transaksie-uitset**, moet heeltemal in 'n transaksie spandeer word. As slegs 'n deel daarvan na 'n ander adres gestuur word, gaan die res na 'n nuwe veranderingsadres. Waarnemers kan aanneem dat hierdie nuwe adres aan die sender behoort, wat privaatheid benadeel.

### Voorbeeld
Om dit te verminder, kan mengdienste of die gebruik van verskeie adresse help om eienaarskap te verdoesel.

## **Sosiale Netwerke & Forum Blootstelling**

Gebruikers deel soms hul Bitcoin-adresse aanlyn, wat dit **maklik maak om die adres aan sy eienaar te koppel**.

## **Transaksiegrafiekontleding**

Transaksies kan as grafieke voorgestel word, wat potensiële verbindings tussen gebruikers onthul op grond van die vloei van fondse.

## **Onnodige Invoerheuristiek (Optimale Veranderingsheuristiek)**

Hierdie heuristiek is gebaseer op die analise van transaksies met meervoudige invoere en uitsette om te raai watter uitset die verandering is wat na die sender terugkeer.

### Voorbeeld
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Indien die toevoeging van meer insette die uitset groter maak as enige enkele inset, kan dit die heuristiek in die war bring.

## **Gedwonge Adres Hergebruik**

Aanvallers kan klein bedrae na voorheen gebruikte adresse stuur, in die hoop dat die ontvanger dit saam met ander insette in toekomstige transaksies gebruik, en sodoende adresse aan mekaar koppel.

### Korrekte Beursiegedrag
Beursies moet voorkom dat munte ontvang op reeds gebruikte, leë adresse om hierdie privaatheidslek te voorkom.

## **Ander Blockchain Analise Tegnieke**

- **Presiese Betalingsbedrae:** Transaksies sonder wisselgeld is waarskynlik tussen twee adresse wat deur dieselfde gebruiker besit word.
- **Ronde Getalle:** 'n Ronde getal in 'n transaksie dui daarop dat dit 'n betaling is, met die nie-ronde uitset wat waarskynlik die wisselgeld is.
- **Beursie Vingerafdrukke:** Verskillende beursies het unieke transaksie-skeppingspatrone, wat analiste in staat stel om die gebruikte sagteware en moontlik die wisselgeldadres te identifiseer.
- **Bedrag & Tydsverbande:** Die bekendmaking van transaksie-tye of -bedrae kan transaksies naspeurbaar maak.

## **Verkeersanalise**

Deur netwerkverkeer te monitor, kan aanvallers moontlik transaksies of blokke aan IP-adresse koppel, wat die privaatheid van gebruikers in gevaar kan bring. Dit is veral waar as 'n entiteit baie Bitcoin-nodes bedryf, wat hul vermoë om transaksies te monitor verbeter.

## Meer
Vir 'n omvattende lys van privaatheidsaanvalle en verdedigings, besoek [Bitcoin Privacy op Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).


# Anonieme Bitcoin Transaksies

## Maniere om Bitcoins Anoniem te Kry

- **Kontant Transaksies**: Bitcoin verkry deur kontant.
- **Alternatiewe Kontant**: Aankoop van geskenkkaarte en dit aanlyn ruil vir bitcoin.
- **Mynbou**: Die mees private metode om bitcoins te verdien is deur mynbou, veral wanneer dit alleen gedoen word, omdat mynbou-poele die IP-adres van die mynwerker kan weet. [Mynbou-poele-inligting](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diefstal**: Teoreties kan die steel van bitcoin 'n ander metode wees om dit anoniem te bekom, alhoewel dit onwettig en nie aanbeveel word nie.

## Mengdienste

Deur 'n mengdiens te gebruik, kan 'n gebruiker **bitcoins stuur** en **verskillende bitcoins in ruil ontvang**, wat dit moeilik maak om die oorspronklike eienaar op te spoor. Dit vereis egter vertroue in die diens om nie logboeke te hou en om die bitcoins werklik terug te gee. Alternatiewe mengopsies sluit Bitcoin-casinos in.

## CoinJoin

**CoinJoin** voeg verskeie transaksies van verskillende gebruikers saam in een, wat die proses vir enigeen wat probeer om insette met uitsette te koppel, bemoeilik. Ten spyte van sy doeltreffendheid kan transaksies met unieke inset- en uitsetgroottes steeds potensieel nagespoor word.

Voorbeeldtransaksies wat moontlik CoinJoin gebruik het, sluit in `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` en `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Vir meer inligting, besoek [CoinJoin](https://coinjoin.io/en). Vir 'n soortgelyke diens op Ethereum, kyk na [Tornado Cash](https://tornado.cash), wat transaksies anonimiseer met fondse van mynwerkers.

## PayJoin

'n Variasie van CoinJoin, **PayJoin** (of P2EP), vermom die transaksie tussen twee partye (bv. 'n kliënt en 'n handelaar) as 'n gewone transaksie, sonder die kenmerkende gelyke uitsette van CoinJoin. Dit maak dit uiters moeilik om op te spoor en kan die algemene-inset-eienaarskap-heuristiek wat deur transaksie-surveillance-entiteite gebruik word, ongeldig maak.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transaksies soos die bogenoemde kan PayJoin wees, wat privaatheid verbeter terwyl dit nie onderskeibaar is van standaard bitcoin-transaksies nie.

**Die gebruik van PayJoin kan tradisionele bewakingsmetodes aansienlik ontwrig**, wat dit 'n belowende ontwikkeling maak in die strewe na transaksionele privaatheid.


# Beste Praktyke vir Privatiteit in Kriptogeldeenhede

## **Balgelykmaak van Beursies Tegnieke**

Om privaatheid en veiligheid te handhaaf, is dit noodsaaklik om beursies met die blokketting te sinchroniseer. Twee metodes steek uit:

- **Volle knoop**: Deur die hele blokketting af te laai, verseker 'n volle knoop maksimum privaatheid. Alle transaksies wat ooit gemaak is, word plaaslik gestoor, wat dit onmoontlik maak vir teenstanders om te identifiseer watter transaksies of adresse die gebruiker belangstel.
- **Kliëntkant blokfiltering**: Hierdie metode behels die skep van filters vir elke blok in die blokketting, wat beursies in staat stel om relevante transaksies te identifiseer sonder om spesifieke belange aan netwerkwaarnemers bloot te stel. Ligte beursies laai hierdie filters af en haal slegs volle blokke binne wanneer 'n ooreenstemming met die gebruiker se adresse gevind word.

## **Die Gebruik van Tor vir Anonimiteit**

Aangesien Bitcoin op 'n eweknie-netwerk werk, word dit aanbeveel om Tor te gebruik om jou IP-adres te verberg en sodoende privaatheid te verbeter wanneer jy met die netwerk skakel.

## **Voorkoming van Adres Hergebruik**

Om privaatheid te beskerm, is dit noodsaaklik om 'n nuwe adres vir elke transaksie te gebruik. Adres hergebruik kan privaatheid in gevaar bring deur transaksies aan dieselfde entiteit te koppel. Moderne beursies ontmoedig adres hergebruik deur hul ontwerp.

## **Strategieë vir Transaksie-Privaatheid**

- **Meervoudige transaksies**: Die opsplitting van 'n betaling in verskeie transaksies kan die transaksiebedrag verdoesel, wat privaatheidsaanvalle voorkom.
- **Vermyding van wisselgeld**: Die keuse vir transaksies wat nie wisselgeld-uitsette vereis nie, verbeter privaatheid deur wisselgeld-opsporingsmetodes te ontwrig.
- **Meervoudige wisselgeld-uitsette**: As die vermyding van wisselgeld nie haalbaar is nie, kan die skep van meervoudige wisselgeld-uitsette steeds privaatheid verbeter.

# **Monero: 'n Baken van Anonimiteit**

Monero spreek die behoefte aan absolute anonimiteit in digitale transaksies aan en stel 'n hoë standaard vir privaatheid.

# **Ethereum: Gas en Transaksies**

## **Begrip van Gas**

Gas meet die berekeningspoging wat nodig is om operasies op Ethereum uit te voer, geprijs in **gwei**. Byvoorbeeld, 'n transaksie wat 2,310,000 gwei (of 0.00231 ETH) kos, behels 'n gaslimiet en 'n basisfooi, met 'n fooi om mynwerkers te motiveer. Gebruikers kan 'n maksimumfooi instel om te verseker dat hulle nie te veel betaal nie, met die oortollige bedrag wat terugbetaal word.

## **Uitvoering van Transaksies**

Transaksies in Ethereum behels 'n afsender en 'n ontvanger, wat beide gebruikers- of slimkontrakadresse kan wees. Hulle vereis 'n fooi en moet gemyn word. Essensiële inligting in 'n transaksie sluit die ontvanger, die afsender se handtekening, waarde, opsionele data, gaslimiet en fooie in. Merkwaardig word die afsender se adres afgelei uit die handtekening, wat die behoefte daaraan in die transaksiedata elimineer.

Hierdie praktyke en meganismes is fundamenteel vir enigiemand wat betrokke wil raak by kriptogeldeenhede terwyl privaatheid en veiligheid vooropgestel word.


## Verwysings

* [https://en.wikipedia.org/wiki/Proof\_of\_stake](https://en.wikipedia.org/wiki/Proof\_of\_stake)
* [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
* [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
* [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
* [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
* [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced\_address\_reuse)


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
