{% hint style="success" %}
Leer & oefen AWS-hacking: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP-hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Controleer de [**abonnementsplannen**](https://github.com/sponsors/carlospolop)!
* **Sluit aan bij de** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of de [**telegramgroep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktrucs door PR's in te dienen bij de** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>
{% endhint %}

## Basiese Konsepte

- **Slimme Kontrakte** word gedefinieer as programme wat op 'n blokketting uitgevoer word wanneer sekere voorwaardes voldoen is, wat ooreenkomste outomatiseer sonder bemiddelaars.
- **Gedekentraliseerde Toepassings (dApps)** bou op slimme kontrakte, met 'n gebruikersvriendelike voorkant en 'n deursigtige, ouditeerbare agterkant.
- **Tokens & Munte** onderskei waar munte as digitale geld dien, terwyl tokens waarde of eienaarskap in spesifieke kontekste verteenwoordig.
- **Hulpprogram Tokens** gee toegang tot dienste, en **Sekerheidstokens** dui bate-eienaarskap aan.
- **DeFi** staan vir Gedekentraliseerde Finansies, wat finansiële dienste sonder sentrale owerhede bied.
- **DEX** en **DAOs** verwys na Gedekentraliseerde Ruilplatforms en Gedekentraliseerde Outonome Organisasies, onderskeidelik.

## Konsensus Meganismes

Konsensusmeganismes verseker veilige en ooreengekome transaksievalidasies op die blokketting:
- **Bewys van Werk (PoW)** steun op rekenkundige krag vir transaksieverifikasie.
- **Bewys van Deelname (PoS)** vereis dat valideerders 'n sekere hoeveelheid tokens moet besit, wat energieverbruik verminder in vergelyking met PoW.

## Bitcoin Essensies

### Transaksies

Bitcoin-transaksies behels die oordrag van fondse tussen adresse. Transaksies word deur digitale handtekeninge gevalideer, wat verseker dat slegs die eienaar van die privaatsleutel oordragte kan inisieer.

#### Sleutelkomponente:

- **Multisignatuurtransaksies** vereis meervoudige handtekeninge om 'n transaksie te magtig.
- Transaksies bestaan uit **inskrywings** (bron van fondse), **uitsette** (bestemming), **fooie** (betaal aan mynwerkers), en **skripte** (transaksiereëls).

### Blikseminetwerk

Mik om Bitcoin se skaalbaarheid te verbeter deur meervoudige transaksies binne 'n kanaal toe te laat, en slegs die finale toestand na die blokketting uit te saai.

## Bitcoin-privasiekwessies

Privasie-aanvalle, soos **Gemeenskaplike Invoereienaarskap** en **UTXO-veranderingsadresopsporing**, benut transaksiepatrone. Strategieë soos **Mengers** en **CoinJoin** verbeter anonimiteit deur transaksieskakels tussen gebruikers te verduister.

## Anoniem Bitcoins verkry

Metodes sluit kontanttransaksies, mynbou, en die gebruik van mengers in. **CoinJoin** meng verskeie transaksies om naspeurbaarheid te bemoeilik, terwyl **PayJoin** CoinJoins as gewone transaksies vermom vir verhoogde privaatheid.


# Bitcoin-privasieaanvalle

# Opsomming van Bitcoin-privasieaanvalle

In die wêreld van Bitcoin is die privaatheid van transaksies en die anonimiteit van gebruikers dikwels onderwerp van kommer. Hier is 'n vereenvoudigde oorsig van verskeie algemene metodes waardeur aanvallers Bitcoin-privasie kan kompromiteer.

## **Gemeenskaplike Invoereienaarskap Aannames**

Dit is oor die algemeen selde dat invoere van verskillende gebruikers in 'n enkele transaksie gekombineer word weens die betrokkenheid van kompleksiteit. Dus word **daar dikwels aanvaar dat twee invoeradresse in dieselfde transaksie aan dieselfde eienaar behoort**.

## **UTXO-veranderingsadresopsporing**

'n UTXO, of **Ongebruikte Transaksie-uitset**, moet heeltemal in 'n transaksie spandeer word. As slegs 'n deel daarvan na 'n ander adres gestuur word, gaan die res na 'n nuwe veranderingsadres. Waarnemers kan aanneem dat hierdie nuwe adres aan die sender behoort, wat privaatheid kompromiteer.

### Voorbeeld
Om dit te verminder, kan mengdienste of die gebruik van verskeie adresse help om eienaarskap te verduister.

## **Sosiale Netwerke & Forum Blootstelling**

Gebruikers deel soms hul Bitcoin-adresse aanlyn, wat dit **maklik maak om die adres aan sy eienaar te koppel**.

## **Transaksiegrafiekontleding**

Transaksies kan as grafieke gevisualiseer word, wat potensiële verbindings tussen gebruikers onthul gebaseer op die vloei van fondse.

## **Onnodige Invoerheuristiek (Optimale Veranderingsheuristiek)**

Hierdie heuristiek is gebaseer op die analise van transaksies met meervoudige invoere en uitsette om te raai watter uitset na die sender terugkeer.

### Voorbeeld
```bash
2 btc --> 4 btc
3 btc     1 btc
```
## **Gedwonge Adres Hergebruik**

Aanvallers kan klein bedrae na voorheen gebruikte adresse stuur, in die hoop dat die ontvanger dit saam met ander insette in toekomstige transaksies gebruik, en sodoende adresse aan mekaar koppel.

### Korrekte Beursiegedrag
Beursies moet vermy om munte te gebruik wat ontvang is op reeds gebruikte, leë adresse om hierdie privaatheidslek te voorkom.

## **Ander Blockchain Analise Tegnieke**

- **Presiese Betalingsbedrae:** Transaksies sonder verandering is waarskynlik tussen twee adresse wat deur dieselfde gebruiker besit word.
- **Ronde Getalle:** 'n Ronde getal in 'n transaksie dui daarop dat dit 'n betaling is, met die nie-ronde uitset wat waarskynlik die verandering is.
- **Beursie Vingerafdrukke:** Verskillende beursies het unieke transaksieskeppingspatrone, wat analiste in staat stel om die gebruikte sagteware te identifiseer en moontlik die veranderingsadres.
- **Bedrag & Tydsamehang:** Die bekendmaking van transaksie tye of bedrae kan transaksies naspeurbaar maak.

## **Verkeersanalise**

Deur netwerkverkeer te monitor, kan aanvallers moontlik transaksies of blokke aan IP adresse koppel, wat gebruikersprivaatheid in gevaar kan bring. Dit is veral waar as 'n entiteit baie Bitcoin knotsdieners bedryf, wat hul vermoë om transaksies te monitor verbeter.

## Meer
Vir 'n omvattende lys van privaatheidsaanvalle en verdedigings, besoek [Bitcoin Privacy op Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).


# Anonieme Bitcoin Transaksies

## Maniere om Bitcoins Anoniem te Kry

- **Kontant Transaksies**: Bitcoin verkry deur kontant.
- **Kontant Alternatiewe**: Koop geskenkkaarte en ruil dit aanlyn vir bitcoin.
- **Mynbou**: Die mees private metode om bitcoins te verdien is deur mynbou, veral wanneer alleen gedoen omdat mynbougroepe die mynwerker se IP-adres kan ken. [Mynbou Groepe Inligting](https://en.bitcoin.it/wiki/Pooled_mining)
- **Diefstal**: Teoreties kan diefstal van bitcoin 'n ander metode wees om dit anoniem te bekom, alhoewel dit onwettig is en nie aanbeveel word nie.

## Mengdienste

Deur 'n mengdiens te gebruik, kan 'n gebruiker **bitcoins stuur** en **verskillende bitcoins terugontvang**, wat dit moeilik maak om die oorspronklike eienaar op te spoor. Dit vereis egter vertroue in die diens om nie logboeke te hou en om werklik die bitcoins terug te gee nie. Alternatiewe mengopsies sluit Bitcoin kasinos in.

## CoinJoin

**CoinJoin** kombineer meervoudige transaksies van verskillende gebruikers in een, wat die proses vir enigiemand wat probeer om insette met uitsette te koppel, bemoeilik. Ten spyte van sy doeltreffendheid, kan transaksies met unieke inset- en uitsetgroottes steeds moontlik nagespeur word.

Voorbeeldtransaksies wat moontlik CoinJoin gebruik het, sluit in `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` en `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Vir meer inligting, besoek [CoinJoin](https://coinjoin.io/en). Vir 'n soortgelyke diens op Ethereum, kyk na [Tornado Cash](https://tornado.cash), wat transaksies anonimiseer met fondse van mynbouers.

## PayJoin

'n Variante van CoinJoin, **PayJoin** (of P2EP), vermom die transaksie tussen twee partye (bv. 'n kliënt en 'n handelaar) as 'n gewone transaksie, sonder die kenmerkende gelyke uitsette van CoinJoin. Dit maak dit uiters moeilik om op te spoor en kan die algemene-inset-eienaarskap heuristiek wat deur transaksie-surveillance entiteite gebruik word, ongeldig maak.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transaksies soos die bogenoemde kan PayJoin wees, wat privaatheid verbeter terwyl dit nie onderskeibaar is van standaard bitcoin-transaksies nie.

**Die gebruik van PayJoin kan tradisionele moniteringsmetodes aansienlik ontwrig**, wat dit 'n belowende ontwikkeling maak in die strewe na transaksionele privaatheid.


# Beste Praktyke vir Privaatheid in Kriptogeldeenhede

## **Bewaarbeurs Synchronisasie Tegnieke**

Om privaatheid en sekuriteit te handhaaf, is dit noodsaaklik om bewaarbeurse met die blokketting te synchroniseer. Twee metodes steek uit:

- **Volle node**: Deur die hele blokketting af te laai, verseker 'n volle node maksimum privaatheid. Alle transaksies wat ooit gemaak is, word plaaslik gestoor, wat dit onmoontlik maak vir teenstanders om te identifiseer in watter transaksies of adresse die gebruiker belangstel.
- **Kliëntkant blokfiltering**: Hierdie metode behels die skep van filters vir elke blok in die blokketting, wat bewaarbeurse in staat stel om relevante transaksies te identifiseer sonder om spesifieke belange aan netwerkwaarnemers bloot te stel. Ligte bewaarbeurse laai hierdie filters af, enige volle blokke wanneer 'n ooreenkoms met die gebruiker se adresse gevind word.

## **Tor benut vir Anonimiteit**

Gegewe dat Bitcoin op 'n ewekansige netwerk werk, word dit aanbeveel om Tor te gebruik om jou IP-adres te verberg, wat privaatheid verbeter wanneer jy met die netwerk interaksie het.

## **Voorkoming van Adres Hergebruik**

Om privaatheid te beskerm, is dit noodsaaklik om vir elke transaksie 'n nuwe adres te gebruik. Adreshergebruik kan privaatheid in gevaar bring deur transaksies aan dieselfde entiteit te koppel. Moderne bewaarbeurse ontmoedig adreshergebruik deur hul ontwerp.

## **Strategieë vir Transaksie Privaatheid**

- **Meervoudige transaksies**: Die opsplitting van 'n betaling in verskeie transaksies kan die transaksiebedrag verberg, privaatheidsaanvalle dwarsboom.
- **Vermy verandering**: Om te kies vir transaksies wat nie veranderingsuitsette benodig nie, verbeter privaatheid deur veranderingsopsporingsmetodes te ontwrig.
- **Meervoudige veranderingsuitsette**: As die vermyding van verandering nie moontlik is nie, kan die skep van meervoudige veranderingsuitsette steeds privaatheid verbeter.

# **Monero: 'n Baken van Anonimiteit**

Monero spreek die behoefte aan absolute anonimiteit in digitale transaksies aan, en stel 'n hoë standaard vir privaatheid.

# **Ethereum: Gas en Transaksies**

## **Begrip van Gas**

Gas meet die rekenkundige poging wat nodig is om operasies op Ethereum uit te voer, geprijs in **gwei**. Byvoorbeeld, 'n transaksie wat 2,310,000 gwei (of 0.00231 ETH) kos, behels 'n gaslimiet en 'n basiskoers, met 'n fooi om myners te motiveer. Gebruikers kan 'n maksimumfooi instel om te verseker dat hulle nie te veel betaal nie, met die oortollige terugbetaal.

## **Uitvoering van Transaksies**

Transaksies in Ethereum behels 'n sender en 'n ontvanger, wat beide gebruiker- of slimkontrakadresse kan wees. Hulle vereis 'n fooi en moet gemyn word. Essensiële inligting in 'n transaksie sluit die ontvanger, die sender se handtekening, waarde, opsionele data, gaslimiet en fooie in. Merkwaardig word die sender se adres afgelei uit die handtekening, wat die behoefte daaraan in die transaksiedata uitskakel.

Hierdie praktyke en meganismes is fundamenteel vir enigeen wat met kriptogeldeenhede wil betrokke raak terwyl hulle privaatheid en sekuriteit prioriteer.


## Verwysings

* [https://en.wikipedia.org/wiki/Proof\_of\_stake](https://en.wikipedia.org/wiki/Proof\_of\_stake)
* [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
* [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
* [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
* [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
* [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced\_address\_reuse)


{% hint style="success" %}
Leer & oefen AWS Hack: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}
