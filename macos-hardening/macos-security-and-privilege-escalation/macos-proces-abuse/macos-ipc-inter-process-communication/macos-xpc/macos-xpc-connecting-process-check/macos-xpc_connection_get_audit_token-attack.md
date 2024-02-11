# macOS xpc\_connection\_get\_audit\_token Aanval

<details>

<summary><strong>Leer AWS-hacking vanaf nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere manieren om HackTricks te ondersteunen:

* Als je je **bedrijf geadverteerd wilt zien in HackTricks** of **HackTricks wilt downloaden in PDF-formaat**, bekijk dan de [**ABONNEMENTSPAKKETTEN**](https://github.com/sponsors/carlospolop)!
* Koop de [**officiële PEASS & HackTricks-merchandise**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), onze collectie exclusieve [**NFT's**](https://opensea.io/collection/the-peass-family)
* **Sluit je aan bij de** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of de [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel je hacktrucs door PR's in te dienen bij de** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

**Voor meer informatie bekijk het originele bericht: [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)**. Dit is een samenvatting:


## Basisinformatie over Mach-berichten

Als je niet weet wat Mach-berichten zijn, begin dan met het controleren van deze pagina:

{% content-ref url="../../../../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../../../../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

Onthoud voorlopig dat ([definitie van hier](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach-berichten worden verzonden via een _mach-poort_, wat een **communicatiekanaal met één ontvanger en meerdere verzenders** is dat is ingebouwd in de mach-kernel. **Meerdere processen kunnen berichten verzenden** naar een mach-poort, maar op elk moment kan **slechts één proces eruit lezen**. Net als bestandsdescriptoren en sockets worden mach-poorten toegewezen en beheerd door de kernel en zien processen alleen een getal, dat ze kunnen gebruiken om aan de kernel aan te geven welke van hun mach-poorten ze willen gebruiken.

## XPC-verbinding

Als je niet weet hoe een XPC-verbinding tot stand komt, bekijk dan:

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## Vuln Samenvatting

Wat interessant is om te weten, is dat de abstractie van XPC een één-op-één verbinding is, maar gebaseerd is op een technologie die **meerdere verzenders kan hebben, dus:**

* Mach-poorten hebben één ontvanger, **meerdere verzenders**.
* De audit token van een XPC-verbinding is de audit token die is **gekopieerd van het meest recent ontvangen bericht**.
* Het verkrijgen van de **audit token** van een XPC-verbinding is cruciaal voor veel **beveiligingscontroles**.

Hoewel de vorige situatie veelbelovend klinkt, zijn er enkele scenario's waarin dit geen problemen zal veroorzaken ([van hier](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

* Audit tokens worden vaak gebruikt voor een autorisatiecontrole om te beslissen of een verbinding moet worden geaccepteerd. Omdat dit gebeurt met behulp van een bericht naar de servicepoort, is er **nog geen verbinding tot stand gebracht**. Meer berichten op deze poort worden gewoon behandeld als extra verbindingsverzoeken. Dus eventuele **controles vóór het accepteren van een verbinding zijn niet kwetsbaar** (dit betekent ook dat binnen `-listener:shouldAcceptNewConnection:` de audit token veilig is). We zijn daarom **op zoek naar XPC-verbindingen die specifieke acties verifiëren**.
* XPC-eventhandlers worden synchroon afgehandeld. Dit betekent dat de eventhandler voor één bericht voltooid moet zijn voordat deze wordt aangeroepen voor het volgende bericht, zelfs op gelijktijdige dispatch-rijen. Dus binnen een **XPC-eventhandler kan de audit token niet worden overschreven** door andere normale (niet-antwoord!) berichten.

Er zijn twee verschillende methoden waarop dit mogelijk kan worden misbruikt:

1. Variant 1:
* De **exploit** maakt verbinding met service **A** en service **B**.
* Service **B** kan een **bevoorrechte functionaliteit** in service A aanroepen die de gebruiker niet kan.
* Service **A** roept **`xpc_connection_get_audit_token`** aan terwijl het **niet** binnen de **eventhandler** voor een verbinding in een **`dispatch_async`** is.
* Dus een **ander bericht kan de Audit Token overschrijven** omdat het asynchroon wordt gedispatched buiten de eventhandler.
* De exploit geeft de **SEND-recht van service A door aan service B**.
* Dus svc **B** zal daadwerkelijk de **berichten** naar service **A** sturen.
* De **exploit** probeert de **bevoorrechte actie aan te roepen**. In een RC svc **A controleert** de autorisatie van deze **actie** terwijl **svc B de Audit token heeft overschreven** (waardoor de exploit toegang heeft tot het aanroepen van de bevoorrechte actie).
2. Variant 2:
* Service **B** kan een **bevoorrechte functionaliteit** in service A aanroepen die de gebruiker niet kan.
* De exploit maakt verbinding met **service A** die de exploit een **bericht stuurt waarop een reactie wordt verwacht** in een specifieke **replay-poort**.
* De exploit stuurt **service B een bericht waarin die antwoordpoort** wordt doorgegeven.
* Wanneer service **B antwoordt**, stuurt het het bericht naar service A, **terwijl** de exploit een ander **bericht naar service A stuurt** om te proberen een bevoorrechte functionaliteit te bereiken en verwacht dat het antwoord van service B de Audit token op het perfecte moment overschrijft (Race Condition).

## Variant 1: xpc\_connection\_get\_audit\_token aanroepen buiten een eventhandler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

* Twee mach-services **`A`** en **`B`** waarmee we beide verbinding kunnen maken (op basis van het sandbox-profiel en de autorisatiecontroles voordat de verbinding wordt geaccepteerd).
* _**A**_ moet een **autorisatiecontrole** hebben voor een specifieke actie die **`B`** kan doorgeven (maar onze app niet kan).
* Bijvoorbeeld, als B bepaalde **rechten** heeft of als het wordt uitgevoerd als **root**, kan het toestaan dat het A vraagt om een bevoorrechte actie uit te voeren.
* Voor deze autorisatiecontrole verkrijgt **`A`** de audit token asynchroon, bijvoorbeeld door `xpc_connection_get_audit_token` aan te
4. Die volgende stap behels die instruksie van `diagnosticd` om monitering van 'n gekose proses te begin (moontlik die gebruiker se eie). Gelyktydig word 'n vloed van roetine 1004-boodskappe na `smd` gestuur. Die doel hiervan is om 'n instrument met verhoogde bevoegdhede te installeer.
5. Hierdie aksie veroorsaak 'n wedloopkondisie binne die `handle_bless`-funksie. Die tydsberekening is krities: die `xpc_connection_get_pid`-funksie-oproep moet die PID van die gebruiker se proses teruggee (aangesien die bevoorregte instrument in die gebruiker se toepassingsbundel bly). Die `xpc_connection_get_audit_token`-funksie, spesifiek binne die `connection_is_authorized`-subroetine, moet egter verwys na die oudit-token wat aan `diagnosticd` behoort.

## Variasie 2: antwoord deurstuur

In 'n XPC (Kruisproseskommunikasie) omgewing, alhoewel gebeurtenishanteerders nie gelyktydig uitgevoer word nie, het die hantering van antwoordboodskappe 'n unieke gedrag. Spesifiek bestaan daar twee onderskeie metodes om boodskappe te stuur wat 'n antwoord verwag:

1. **`xpc_connection_send_message_with_reply`**: Hierdie XPC-boodskap word ontvang en verwerk op 'n aangewese ry.
2. **`xpc_connection_send_message_with_reply_sync`**: Daarenteen word die XPC-boodskap in hierdie metode ontvang en verwerk op die huidige verspreidingsry.

Hierdie onderskeid is van kritieke belang omdat dit die moontlikheid bied dat **antwoordpakkette gelyktydig gepars word met die uitvoering van 'n XPC-gebeurtenishanterer**. Merkwaardig genoeg implementeer `_xpc_connection_set_creds` sluiting om te beskerm teen die gedeeltelike oorskrywing van die oudit-token, maar dit bied nie hierdie beskerming vir die hele verbindingsvoorwerp nie. Gevolglik skep dit 'n kwesbaarheid waar die oudit-token vervang kan word gedurende die interval tussen die parsing van 'n pakkie en die uitvoering van sy gebeurtenishanterer.

Om van hierdie kwesbaarheid gebruik te maak, is die volgende opset vereis:

- Twee mach-diens
