# Shambulizi la xpc\_connection\_get\_audit\_token kwenye macOS

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA USAJILI**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha** [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

**Kwa habari zaidi angalia chapisho la asili:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Hii ni muhtasari:

## Taarifa Msingi za Ujumbe wa Mach

Ikiwa haujui ni nini Ujumbe wa Mach anza kwa kuangalia ukurasa huu:

{% content-ref url="../../../../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../../../../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

Kwa sasa kumbuka ([ufafanuzi kutoka hapa](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Ujumbe wa Mach hutumwa juu ya _mach port_, ambayo ni **mpokeaji mmoja, watoaji wengi wa mawasiliano** iliyojengwa ndani ya kernel ya mach. **Michakato mingi inaweza kutuma ujumbe** kwa mach port, lakini wakati wowote **mpokeaji mmoja tu anaweza kusoma kutoka kwake**. Kama vile vitambulisho vya faili na soketi, mach ports hupewa na kusimamiwa na kernel na michakato huona nambari ya nambari, ambayo wanaweza kutumia kuashiria kernel ni mach ports yao wanataka kutumia.

## Uunganisho wa XPC

Ikiwa haujui jinsi uhusiano wa XPC unavyoundwa angalia:

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## Muhtasari wa Udhaifu

Jambo linalovutia kujua ni kwamba **kuhakikisha ya XPC ni uhusiano wa moja kwa moja**, lakini inategemea teknolojia ambayo **inaweza kuwa na watoaji wengi**, hivyo:

* Mach ports ni mpokeaji mmoja, **watoaji wengi**.
* Audit token ya uhusiano wa XPC ni token ya ukaguzi wa **iliyochukuliwa kutoka kwa ujumbe uliopokelewa hivi karibuni zaidi**.
* Kupata **audit token** ya uhusiano wa XPC ni muhimu kwa **ukaguzi wa usalama** mengi.

Ingawa hali iliyopita inasikika kuahidi kuna hali ambapo hii haitasababisha matatizo ([kutoka hapa](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

* Tokeni za ukaguzi mara nyingi hutumiwa kwa ukaguzi wa idhini kuamua ikiwa kukubali uhusiano. Kwa kuwa hii hufanyika kwa kutumia ujumbe kwa bandari ya huduma, **hakuna uhusiano ulioanzishwa bado**. Ujumbe zaidi kwenye bandari hii utashughulikiwa kama maombi ya uhusiano ya ziada. Kwa hivyo **ukaguzi kabla ya kukubali uhusiano sio hatarini** (hii pia inamaanisha kuwa ndani ya `-listener:shouldAcceptNewConnection:` tokeni ya ukaguzi iko salama). Kwa hivyo **tunatafuta uhusiano wa XPC ambao huthibitisha hatua maalum**.
* Wachanganuzi wa matukio ya XPC hushughulikiwa kwa usawazishaji. Hii inamaanisha kuwa mchanganuzi wa tukio kwa ujumbe mmoja lazima ukamilike kabla ya kuita kwa ujumbe ufuatao, hata kwenye foleni za kutuma wakati mmoja. Kwa hivyo ndani ya **mchanganuzi wa tukio la XPC tokeni ya ukaguzi haiwezi kubadilishwa** na ujumbe wa kawaida (si majibu!) mwingine.

Kuna njia mbili tofauti ambazo hii inaweza kutumika:

1. Variant1:
* **Shambulizi** linajiunga na huduma **A** na huduma **B**
* Huduma **B** inaweza kuita **kazi ya kipekee** katika huduma **A** ambayo mtumiaji hawezi
* Huduma **A** inaita **`xpc_connection_get_audit_token`** wakati _**si**_ ndani ya **mchanganuzi wa tukio** kwa uhusiano katika **`dispatch_async`**.
* Kwa hivyo **ujumbe tofauti unaweza kubadilisha Audit Token** kwa sababu unatuma kwa kutumwa kwa asinkroni nje ya mchanganuzi wa tukio.
* Shambulizi linapitisha **huduma B haki ya KUTUMA kwa huduma A**.
* Kwa hivyo svc **B** itakuwa **kutuma** **ujumbe** kwa huduma **A**.
* **Shambulizi** jaribu **kuita** **hatua ya kipekee.** Katika RC svc **A** **huthibitisha** idhini ya **hatua** hii wakati **svc B ilibadilisha Tokeni ya Ukaguzi** (ikimpa shambulizi upatikanaji wa kuita hatua ya kipekee).
2. Variant 2:
* Huduma **B** inaweza kuita **kazi ya kipekee** katika huduma **A** ambayo mtumiaji hawezi
* Shambulizi linajiunga na **huduma A** ambayo **inatuma** shambulizi ujumbe ukitarajia majibu katika **bandari ya majibu** maalum.
* Shambulizi inatuma **huduma** B ujumbe ukipitisha **ile bandari ya majibu**.
* Wakati huduma **B inajibu**, inatuma ujumbe kwa huduma **A**, **wakati** **shambulizi** inatuma ujumbe **tofauti kwa huduma A** kujaribu **kufikia kazi ya kipekee** na kutarajia majibu kutoka kwa huduma B itabadilisha Tokeni ya Ukaguzi katika wakati kamili (Hali ya Mashindano).

## Variant 1: kuita xpc\_connection\_get\_audit\_token nje ya mchanganuzi wa tukio <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Hali:

* Huduma mbili za mach **`A`** na **`B`** ambazo tunaweza kujiunga nazo (kulingana na wasifu wa sanduku la mchanga na ukaguzi kabla ya kukubali uhusiano).
* _**A**_ lazima awe na **ukaguzi wa idhini** kwa hatua maalum ambayo **`B`** inaweza kupitisha (lakini programu yetu haiwezi).
* Kwa mfano, ikiwa B ana **haki za kibali** au inaendeshwa kama **root**, inaweza kumruhusu kuomba A kutekeleza hatua ya kipekee.
* Kwa ukaguzi huu wa idhini, **`A`** inapata tokeni ya ukaguzi kwa njia ya asinkroni, kwa mfano kwa kuita `xpc_connection_get_audit_token` kutoka **`dispatch_async`**.

{% hint style="danger" %}
Katika kesi hii, mshambuliaji anaweza kuzindua **Hali ya Mashindano** kufanya **shambulizi** ambalo **linaiomba A kutekeleza hatua** mara kadhaa wakati **B inatuma ujumbe kwa `A`**. Wakati RC inafanikiwa, **tokeni ya ukaguzi** ya **B** itakopiwa kwenye kumbukumbu **wakati** ombi la **shambulizi** letu linashughulikiwa na A, ikimpa **upatikanaji wa hatua ya kipekee ambayo B pekee angeweza kuomba**.
{% endhint %}

Hii ilitokea na **`A`** kama `smd` na **`B`** kama `diagnosticd`. Kazi [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) kutoka smb inaweza kutumika kufunga zana mpya ya msaidizi wa kipekee (kama **root**). Ikiwa **mchakato unaoendeshwa kama root unawasiliana** na **smd**, hakuna ukaguzi mwingine utafanywa.

Kwa hivyo, huduma **B** ni **`diagnosticd`** kwa sababu inaendeshwa kama **root** na inaweza kutumika kufuatilia mchakato, kwa hivyo mara tu ufuatiliaji unapoanza, ita **tuma ujumbe zaidi ya moja kwa sekunde.**

Kufanya shambulizi:

1. Anzisha **ujumbe** kwa huduma iliyoitwa `smd` kwa kutumia itifaki ya XPC ya kawaida.
2. Unda **ujumbe wa pili** kwa `diagnosticd`. Tofauti na utaratibu wa kawaida, badala ya kuunda na kutuma mach ports mpya mbili, haki ya kutuma ya mteja inabadilishwa na nakala ya **haki ya kutuma** inayohusishwa na uhusiano wa `smd`.
3. Kama matokeo, ujumbe wa XPC unaweza kutumwa kwa `diagnosticd`, lakini majibu kutoka `diagnosticd` yanaelekezwa tena kwa `smd`. Kwa `smd`, inaonekana kana kwamba ujumbe kutoka kwa mtumiaji na `diagnosticd` unatoka kwa uhusiano mmoja.

![Picha inayoonyesha mchakato wa shambulizi](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)
4. Hatua inayofuata ni kuagiza `diagnosticd` kuanza kufuatilia mchakato uliochaguliwa (labda wa mtumiaji mwenyewe). Kwa wakati huo huo, mafuriko ya ujumbe wa kawaida wa 1004 hutumwa kwa `smd`. Lengo hapa ni kusakinisha chombo chenye mamlaka ya juu.
5. Hatua hii inachochea hali ya mashindano ndani ya kazi ya `handle_bless`. Wakati ni muhimu: wito wa kazi ya `xpc_connection_get_pid` lazima irudishe PID ya mchakato wa mtumiaji (kwa kuwa chombo cha mamlaka kiko kwenye mfuko wa programu ya mtumiaji). Walakini, kazi ya `xpc_connection_get_audit_token`, kwa kina ndani ya subroutine ya `connection_is_authorized`, lazima itaje alama ya ukaguzi inayomilikiwa na `diagnosticd`.

## Tofauti 2: kusonga majibu

Katika mazingira ya XPC (Mawasiliano kati ya Mchakato), ingawa wakusanyaji wa matukio hawatekelezi kwa wakati mmoja, kushughulikia ujumbe wa majibu kuna tabia ya kipekee. Kwa kina, kuna njia mbili tofauti za kutuma ujumbe ambao unatarajia majibu:

1. **`xpc_connection_send_message_with_reply`**: Hapa, ujumbe wa XPC unapokelewa na kusindika kwenye foleni iliyoteuliwa.
2. **`xpc_connection_send_message_with_reply_sync`**: Kinyume chake, kwa njia hii, ujumbe wa XPC unapokelewa na kusindika kwenye foleni ya kutolewa ya sasa.

Tofauti hii ni muhimu kwa sababu inaruhusu uwezekano wa **pakiti za majibu kuchambuliwa kwa wakati mmoja na utekelezaji wa kusindika kwa tukio la XPC**. Hasa, wakati `_xpc_connection_set_creds` inatekeleza kufunga ili kulinda dhidi ya kubadilisha sehemu ya alama ya ukaguzi, haielekezi ulinzi huu kwa kitu cha uhusiano mzima. Kwa hivyo, hii inaunda udhaifu ambapo alama ya ukaguzi inaweza kubadilishwa wakati wa kipindi kati ya kuchambua kwa pakiti na utekelezaji wa kusindika tukio lake.

Kutumia udhaifu huu, usanidi ufuatao unahitajika:

* Huduma mbili za mach, zinazojulikana kama **`A`** na **`B`**, zote zikiweza kuanzisha uhusiano.
* Huduma **`A`** inapaswa kujumuisha ukaguzi wa idhini kwa hatua maalum ambayo **`B`** pekee anaweza kutekeleza (programu ya mtumiaji hawezi).
* Huduma **`A`** inapaswa kutuma ujumbe unaotarajia majibu.
* Mtumiaji anaweza kutuma ujumbe kwa **`B`** ambao itajibu.

Mchakato wa kutumia udhaifu huu unajumuisha hatua zifuatazo:

1. Subiri huduma **`A`** itume ujumbe unaotarajia majibu.
2. Badala ya kujibu moja kwa moja kwa **`A`**, bandari ya majibu inatekwa na kutumika kutuma ujumbe kwa huduma **`B`**.
3. Kisha, ujumbe unaohusisha hatua iliyozuiwa unatuma, ukitarajia kwamba utasindika kwa wakati mmoja na jibu kutoka kwa **`B`**.

Hapa chini ni uwakilishi wa picha wa mazingira ya shambulio lililoelezwa:

![https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png](../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Matatizo ya Ugunduzi

* **Matatizo katika Kupata Mifano**: Kutafuta matumizi ya `xpc_connection_get_audit_token` ilikuwa changamoto, kwa njia ya kudumu na kwa njia ya kudumu.
* **Mbinu**: Frida ilitumika kufunga kazi ya `xpc_connection_get_audit_token`, ikichuja wito usiotoka kwa wakusanyaji wa matukio. Walakini, njia hii ilikuwa imezuiliwa kwa mchakato uliofungwa na ilihitaji matumizi ya moja kwa moja.
* **Zana za Uchambuzi**: Zana kama IDA/Ghidra zilitumika kuchunguza huduma za mach zinazoweza kufikiwa, lakini mchakato ulichukua muda mrefu, uliochanganywa na wito unaojumuisha hifadhi iliyoshirikiwa ya dyld.
* **Vikwazo vya Uandishi wa Script**: Jaribio la kuandika skripti ya uchambuzi kwa wito wa `xpc_connection_get_audit_token` kutoka kwa vitengo vya `dispatch_async` vilizuiliwa na ugumu katika kuchambua vitengo na mwingiliano na hifadhi iliyoshirikiwa ya dyld.

## Marekebisho <a href="#the-fix" id="the-fix"></a>

* **Masuala Yaliyoripotiwa**: Ripoti ilitumwa kwa Apple ikielezea masuala ya jumla na maalum yaliyopatikana ndani ya `smd`.
* **Jibu la Apple**: Apple ilishughulikia suala katika `smd` kwa kubadilisha `xpc_connection_get_audit_token` na `xpc_dictionary_get_audit_token`.
* **Asili ya Marekebisho**: Kazi ya `xpc_dictionary_get_audit_token` inachukuliwa kuwa salama kwani inapata alama ya ukaguzi moja kwa moja kutoka kwa ujumbe wa mach uliounganishwa na ujumbe wa XPC uliopokelewa. Walakini, sio sehemu ya API ya umma, kama `xpc_connection_get_audit_token`.
* **Ukosefu wa Marekebisho ya Kina Zaidi**: Bado haijulikani kwa nini Apple haikutekeleza marekebisho makubwa zaidi, kama kutupa ujumbe usioendana na alama ya ukaguzi iliyohifadhiwa ya uhusiano. Uwezekano wa mabadiliko halali ya alama ya ukaguzi katika hali fulani (k.m., matumizi ya `setuid`) inaweza kuwa sababu.
* **Hali ya Sasa**: Suala hili linaendelea katika iOS 17 na macOS 14, likiwa changamoto kwa wale wanaotafuta kugundua na kuelewa.
