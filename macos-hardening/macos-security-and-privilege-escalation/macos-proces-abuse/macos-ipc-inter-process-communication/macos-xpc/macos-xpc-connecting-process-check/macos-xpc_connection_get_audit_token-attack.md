# macOS xpc\_connection\_get\_audit\_token Aanval

<details>

<summary><strong>Leer AWS hak vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien jou **maatskappy geadverteer in HackTricks** of **HackTricks aflaai in PDF-formaat** Kyk na die [**INSKRYWINGSPLANNE**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**Die PEASS Familie**](https://opensea.io/collection/the-peass-family), ons versameling van eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Deel jou haktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**Vir verdere inligting kyk na die oorspronklike pos:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Hierdie is 'n opsomming:

## Mach-boodskappe Basiese Inligting

As jy nie weet wat Mach-boodskappe is nie, begin deur hierdie bladsy te kyk:

{% content-ref url="../../" %}
[..](../../)
{% endcontent-ref %}

Vir die oomblik onthou dat ([definisie vanaf hier](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach-boodskappe word oor 'n _mach-poort_ gestuur, wat 'n **enkele ontvanger, meervoudige sender kommunikasie** kanaal is wat in die mach-kernel ingebou is. **Meervoudige prosesse kan boodskappe** na 'n mach-poort stuur, maar op enige punt kan net **'n enkele proses daarvan lees**. Net soos lêerbeskrywers en sokkette, word mach-poorte toegewys en bestuur deur die kernel en sien prosesse slegs 'n heelgetal, wat hulle kan gebruik om aan te dui aan die kernel watter van hul mach-poorte hulle wil gebruik.

## XPC Verbinding

As jy nie weet hoe 'n XPC-verbinding tot stand gebring word nie, kyk:

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## Kwetsbaarheid Opsomming

Wat vir jou interessant is om te weet, is dat **XPC se abstraksie 'n een-tot-een verbinding is**, maar dit is gebaseer op 'n tegnologie wat **meervoudige senders kan hê, soos:**

* Mach-poorte is enkele ontvanger, **meervoudige sender**.
* Die oudit-token van 'n XPC-verbinding is die oudit-token van **gekopieer van die mees onlangs ontvange boodskap**.
* Die verkryging van die **oudit-token** van 'n XPC-verbinding is krities vir baie **sekuriteitskontroles**.

Alhoewel die vorige situasie belowend klink, is daar enkele scenario's waar dit nie probleme gaan veroorsaak nie ([vanaf hier](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

* Oudit-tokens word dikwels gebruik vir 'n magtigingskontrole om te besluit of 'n verbinding aanvaar moet word. Aangesien dit gebeur deur 'n boodskap na die dienspoort te stuur, is daar **nog geen verbinding tot stand gebring nie**. Meer boodskappe op hierdie poort sal net hanteer word as addisionele verbindingsversoeke. Dus is enige **kontroles voor die aanvaarding van 'n verbinding nie kwesbaar nie** (dit beteken ook dat binne `-listener:shouldAcceptNewConnection:` die oudit-token veilig is). Ons is dus **op soek na XPC-verbindings wat spesifieke aksies verifieer**.
* XPC-gebeurtenishanteerders word sinchronies hanteer. Dit beteken dat die gebeurtenishanterer vir een boodskap voltooi moet word voordat dit vir die volgende een geroep word, selfs op gelyktydige verspreidingsbane. Dus binne 'n **XPC-gebeurtenishanterer kan die oudit-token nie oorskryf word** deur ander normale (nie-antwoord!) boodskappe nie.

Twee verskillende metodes waardeur dit uitgebuit kan word:

1. Variant1:
* **Exploit verbind** met diens **A** en diens **B**
* Diens **B** kan 'n **bevoorregte funksionaliteit** in diens A aanroep wat die gebruiker nie kan nie
* Diens **A** roep **`xpc_connection_get_audit_token`** aan terwyl _**nie**_ binne die **gebeurtenishanterer** vir 'n verbinding in 'n **`dispatch_async`** nie.
* Dus kan 'n **verskillende** boodskap die **Oudit-token oorskryf** omdat dit asinkronies buite die gebeurtenishanterer versprei word.
* Die aanval gee die **SEND-reg aan diens A aan diens B**.
* So sal diens **B eintlik die boodskappe** aan diens **A stuur**.
* Die **aanval** probeer om die **bevoorregte aksie aan te roep.** In 'n RC diens **A** **kontroleer** die magtiging van hierdie **aksie** terwyl **diens B die Oudit-token oorskryf** het (wat die aanval toegang gee om die bevoorregte aksie aan te roep).
2. Variant 2:
* Diens **B** kan 'n **bevoorregte funksionaliteit** in diens A aanroep wat die gebruiker nie kan nie
* Aanval verbind met **diens A** wat die aanval 'n **boodskap stuur wat 'n antwoord verwag** in 'n spesifieke **herhaalpoort**.
* Aanval stuur **diens** B 'n boodskap wat **daardie antwoordpoort** deurgee.
* Wanneer diens **B antwoord**, stuur dit die boodskap na diens A, **terwyl** die **aanval** 'n verskillende **boodskap na diens A stuur** wat probeer om 'n bevoorregte funksionaliteit te bereik en verwag dat die antwoord van diens B die Oudit-token in die perfekte oomblik sal oorskryf (Race Condition).

## Variant 1: xpc\_connection\_get\_audit\_token aanroep buite 'n gebeurtenishanterer <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

* Twee mach-diens **`A`** en **`B`** waaraan ons albei kan koppel (gebaseer op die sandboksprofiel en die magtigingskontroles voor die aanvaarding van die verbinding).
* _**A**_ moet 'n **magtigingskontrole** hê vir 'n spesifieke aksie wat **`B`** kan deurgee (maar ons program kan nie).
* Byvoorbeeld, as B sekere **bevoegdhede** het of as **root** uitgevoer word, kan dit hom toelaat om A te vra om 'n bevoorregte aksie uit te voer.
* Vir hierdie magtigingskontrole verkry **`A`** die oudit-token asinkronies, byvoorbeeld deur `xpc_connection_get_audit_token` vanaf **`dispatch_async`** te roep.

{% hint style="danger" %}
In hierdie geval kan 'n aanvaller 'n **Race Condition** veroorsaak deur 'n **aanval** te maak wat **A vra om 'n aksie uit te voer** verskeie kere terwyl **B boodskappe na `A` stuur**. Wanneer die RC **suksesvol** is, sal die **oudit-token** van **B** in die geheue gekopieer word **terwyl** die versoek van ons **aanval** deur A hanteer word, wat dit **toegang gee tot die bevoorregte aksie wat net B kon aanvra**.
{% endhint %}

Dit het met **`A`** as `smd` en **`B`** as `diagnosticd` gebeur. Die funksie [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) van smb kan gebruik word om 'n nuwe bevoorregte hulpmiddel te installeer (as **root**). As 'n **proses wat as root uitgevoer word** **smd** kontak, sal geen ander kontroles uitgevoer word nie.

Daarom is die diens **B** **`diagnosticd`** omdat dit as **root** uitgevoer word en gebruik kan word om 'n proses te **monitor**, so sodra die monitering begin het, sal dit **meervoudige boodskappe per sekonde stuur.**

Om die aanval uit te voer:

1. Begin 'n **verbinding** met die diens genaamd `smd` deur die standaard XPC-protokol te gebruik.
2. Vorm 'n sekondêre **verbinding** met `diagnosticd`. In teenstelling met die normale prosedure, in plaas daarvan om twee nuwe mach-poorte te skep en te stuur, word die kliëntpoort sendreg vervang met 'n duplikaat van die **sendreg** wat geassosieer word met die `smd`-verbinding.
3. As gevolg hiervan kan XPC-boodskappe na `diagnosticd` gestuur word, maar antwoorde van `diagnosticd` word na `smd` omgelei. Vir `smd` lyk dit asof die boodskappe van beide die gebruiker en `diagnosticd` van dieselfde verbinding afkomstig is.

![Beeld wat die aanvalproses uitbeeld](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Die volgende stap behels om `diagnosticd` te instrueer om die monitering van 'n gekose proses te begin (moontlik die gebruiker se eie). Gelyktydig word 'n vloed van rutine 1004-boodskappe na `smd` gestuur. Die doel hier is om 'n hulpmiddel met verhoogde bevoegdhede te installeer.
5. Hierdie aksie veroorsaak 'n wedloopstoestand binne die `handle_bless`-funksie. Die tydsberekening is krities: die `xpc_connection_get_pid`-funksieoproep moet die PID van die gebruiker se proses teruggee (aangesien die bevoorregte instrument in die gebruiker se toepassingsbundel woon). Die `xpc_connection_get_audit_token`-funksie, spesifiek binne die `connection_is_authorized`-subroetine, moet egter verwys na die oudit-token wat aan `diagnosticd` behoort.

## Variante 2: antwoord deurstuur

In 'n XPC (Kruisproseskommunikasie) omgewing, alhoewel gebeurtenishanteerders nie gelyktydig uitgevoer word nie, het die hantering van antwoordboodskappe 'n unieke gedrag. Spesifiek bestaan daar twee onderskeie metodes vir die stuur van boodskappe wat 'n antwoord verwag:

1. **`xpc_connection_send_message_with_reply`**: Hier word die XPC-boodskap ontvang en verwerk op 'n aangewese ry.
2. **`xpc_connection_send_message_with_reply_sync`**: Omgekeerd, in hierdie metode word die XPC-boodskap ontvang en verwerk op die huidige verspreidingsry.

Hierdie onderskeid is noodsaaklik omdat dit die moontlikheid bied vir **antwoordpakketten wat gelyktydig met die uitvoering van 'n XPC-gebeurtenishanterer ontleed kan word**. Merkwaardig, terwyl `_xpc_connection_set_creds` wel sluiting implementeer om teen die gedeeltelike oorskrywing van die oudit-token te beskerm, strek dit nie hierdie beskerming uit na die hele verbindingsvoorwerp nie. Gevolglik skep dit 'n kwesbaarheid waar die oudit-token vervang kan word gedurende die interval tussen die ontleding van 'n pakkie en die uitvoering van sy gebeurtenishanterer.

Om hierdie kwesbaarheid uit te buit, is die volgende opstelling vereis:

* Twee mach-diens, bekend as **`A`** en **`B`**, wat albei 'n verbinding kan tot stand bring.
* Diens **`A`** moet 'n magtigingskontrole insluit vir 'n spesifieke aksie wat slegs **`B`** kan uitvoer (die gebruiker se aansoek kan nie).
* Diens **`A`** moet 'n boodskap stuur wat 'n antwoord verwag.
* Die gebruiker kan 'n boodskap na **`B`** stuur waarop dit sal reageer.

Die uitbuitingsproses behels die volgende stappe:

1. Wag vir diens **`A`** om 'n boodskap te stuur wat 'n antwoord verwag.
2. In plaas daarvan om direk aan **`A`** te antwoord, word die antwoordpoort gekaap en gebruik om 'n boodskap aan diens **`B`** te stuur.
3. Daarna word 'n boodskap wat die verbode aksie behels, gestuur, met die verwagting dat dit gelyktydig met die antwoord van **`B`** verwerk sal word.

Hieronder is 'n visuele voorstelling van die beskryfde aanvalscenario:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../.gitbook/assets/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Ontdekkingsprobleme

* **Moeilikheid om Instansies te Vind**: Die soektog na instansies van `xpc_connection_get_audit_token`-gebruik was uitdagend, beide staties en dinamies.
* **Metodologie**: Frida is gebruik om die `xpc_connection_get_audit_token`-funksie te haak, waarby oproepe wat nie van gebeurtenishanteerders afkomstig is, gefiltreer is. Hierdie metode was egter beperk tot die gehaakte proses en het aktiewe gebruik vereis.
* **Analisegereedskap**: Gereedskap soos IDA/Ghidra is gebruik om bereikbare mach-diens te ondersoek, maar die proses was tydrowend, gekompliseer deur oproepe wat die dyld-gedeelde kas betrek.
* **Skripsiebeperkings**: Pogings om die analise vir oproepe na `xpc_connection_get_audit_token` vanaf `dispatch_async`-blokke te skrip, is bemoeilik deur kompleksiteite in die ontleding van blokke en interaksies met die dyld-gedeelde kas.

## Die regstelling <a href="#the-fix" id="the-fix"></a>

* **Gerapporteerde Kwessies**: 'n Verslag is aan Apple voorgelê wat die algemene en spesifieke kwessies wat binne `smd` gevind is, beskryf.
* **Apple se Reaksie**: Apple het die probleem in `smd` aangespreek deur `xpc_connection_get_audit_token` met `xpc_dictionary_get_audit_token` te vervang.
* **Aard van die Regstelling**: Die `xpc_dictionary_get_audit_token`-funksie word as veilig beskou omdat dit die oudit-token direk van die mach-boodskap wat aan die ontvang XPC-boodskap gekoppel is, terugkry. Dit is egter nie deel van die openbare API nie, soortgelyk aan `xpc_connection_get_audit_token`.
* **Afswaai van 'n Breër Regstelling**: Dit bly onduidelik waarom Apple nie 'n meer omvattende regstelling geïmplementeer het nie, soos die verwerp van boodskappe wat nie ooreenstem met die gestoorde oudit-token van die verbinding nie. Die moontlikheid van legitieme oudit-tokenveranderings in sekere scenario's (bv. `setuid`-gebruik) mag 'n faktor wees.
* **Huidige Stand**: Die probleem bly voortbestaan in iOS 17 en macOS 14, wat 'n uitdaging vir diegene wat dit wil identifiseer en verstaan, inhou.
