# Shambulizi la xpc\_connection\_get\_audit\_token kwenye macOS

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**Kwa habari zaidi angalia chapisho asili: [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)**. Hii ni muhtasari:


## Habari Msingi kuhusu Mach Messages

Ikiwa haujui ni nini Mach Messages, anza kwa kuangalia ukurasa huu:

{% content-ref url="../../../../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../../../../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

Kwa sasa kumbuka kuwa ([ufafanuzi kutoka hapa](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages hutumwa kupitia _mach port_, ambayo ni **njia ya mawasiliano ya mpokeaji mmoja, watumaji wengi** iliyojengwa ndani ya kernel ya mach. **Mchakato mmoja unaweza kutuma ujumbe** kwenye mach port, lakini wakati wowote **mchakato mmoja tu unaweza kusoma kutoka kwake**. Kama vile file descriptors na sockets, mach ports zinatengwa na kusimamiwa na kernel na michakato huona nambari tu, ambayo wanaweza kutumia kuonyesha kernel ni mach ports yao wanayotaka kutumia.

## XPC Connection

Ikiwa haujui jinsi uhusiano wa XPC unavyoundwa, angalia:

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## Muhtasari wa Kuziba

Jambo linalovutia kujua ni kwamba **uhusiano wa XPC ni uhusiano wa mtu-mmoja-kwa-mtu-mmoja**, lakini unategemea teknolojia ambayo **inaweza kuwa na watumaji wengi, kwa hivyo:**

* Mach ports ni mpokeaji mmoja, **watumaji wengi**.
* Kitambulisho cha ukaguzi wa uhusiano wa XPC ni kitambulisho cha ukaguzi **kimekopwa kutoka kwa ujumbe uliopokelewa hivi karibuni zaidi**.
* Kupata **kitambulisho cha ukaguzi** wa uhusiano wa XPC ni muhimu kwa ukaguzi wa usalama nyingi.

Ingawa hali iliyotangulia inasikika kuahidi, kuna hali ambapo hii haitasababisha matatizo ([kutoka hapa](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

* Vitambulisho vya ukaguzi mara nyingi hutumiwa kwa ukaguzi wa idhini ili kuamua ikiwa kukubali uhusiano. Kwa kuwa hii inatokea kwa kutumia ujumbe kwenye bandari ya huduma, **hakuna uhusiano ulioanzishwa bado**. Ujumbe zaidi kwenye bandari hii utashughulikiwa kama maombi ya uhusiano ya ziada. Kwa hivyo, **ukaguzi kabla ya kukubali uhusiano hautakuwa na udhaifu** (hii pia inamaanisha kuwa ndani ya `-listener:shouldAcceptNewConnection:` kitambulisho cha ukaguzi ni salama). Kwa hivyo, **tunatafuta uhusiano wa XPC ambao unathibitisha hatua maalum**.
* Wachanganuzi wa tukio la XPC hushughulikiwa kwa usawazishaji. Hii inamaanisha kuwa mchanganuzi wa tukio kwa ujumbe mmoja lazima ukamilike kabla ya kuita kwa ujumbe unaofuata, hata kwenye foleni za kutuma wakati huo huo. Kwa hivyo ndani ya **mchanganuzi wa tukio la XPC kitambulisho cha ukaguzi hakiwezi kuandikwa tena** na ujumbe wa kawaida (sio majibu!) mengine.

Kuna njia mbili tofauti ambazo hii inaweza kudukuliwa:

1. Variant1:
* **Kudukua** **kuunganisha** kwa huduma **A** na huduma **B**
* Huduma **B** inaweza kuita **kazi yenye mamlaka** katika huduma A ambayo mtumiaji hawezi
* Huduma **A** inaita **`xpc_connection_get_audit_token`** wakati _**si**_ ndani ya **mchanganuzi wa tukio** kwa uhusiano katika **`dispatch_async`**.
* Kwa hivyo ujumbe **tofauti** unaweza **kuandika upya Kitambulisho cha Ukaguzi** kwa sababu inatumiwa kwa njia ya kusambazwa kwa asynchronously nje ya mchanganuzi wa tukio.
* Kudukua inapitisha kwa huduma **B haki ya KUTUMA kwa huduma A**.
* Kwa hivyo svc **B** itakuwa kweli **inatuma** **ujumbe** kwa huduma **A**.
* Kudukua inajaribu **kuita** **hatua yenye mamlaka.** Katika RC svc **A inakagua** idhini ya **hatua** hii wakati **svc B imeandika upya Kitambulisho cha Ukaguzi** (ikitoa kudukua upatikanaji wa kuita hatua yenye mamlaka).
2. Variant 2:
* Huduma **B** inaweza kuita **kazi yenye mamlaka** katika huduma A ambayo mtumiaji hawezi
* Kudukua inaunganisha na huduma **A** ambayo **inatuma** kudukua **ujumbe unaotarajia majibu** kwenye **bandari ya majibu** maalum.
* Kudukua inatuma huduma
4. Hatua inayofuata inahusisha kuiagiza `diagnosticd` kuanzisha ufuatiliaji wa mchakato uliochaguliwa (labda mchakato wa mtumiaji mwenyewe). Kwa wakati huo huo, mafuriko ya ujumbe wa kawaida wa 1004 yanatumwa kwa `smd`. Lengo hapa ni kusakinisha zana yenye mamlaka ya juu.
5. Hatua hii inasababisha hali ya ushindani ndani ya kazi ya `handle_bless`. Wakati ni muhimu: wito wa kazi ya `xpc_connection_get_pid` lazima urejeshe PID ya mchakato wa mtumiaji (kwa kuwa zana yenye mamlaka ya juu iko katika mfuko wa programu ya mtumiaji). Walakini, wito wa kazi ya `xpc_connection_get_audit_token`, hasa ndani ya subroutine ya `connection_is_authorized`, lazima irejelee alama ya ukaguzi inayomilikiwa na `diagnosticd`.

## Variant 2: kuhamisha majibu

Katika mazingira ya XPC (Mawasiliano kati ya Mchakato), ingawa wakurugenzi wa tukio hawatekelezi kwa wakati mmoja, kushughulikia ujumbe wa majibu kuna tabia ya pekee. Kwa usahihi, kuna njia mbili tofauti za kutuma ujumbe ambao unatarajia majibu:

1. **`xpc_connection_send_message_with_reply`**: Hapa, ujumbe wa XPC unapokelewa na kusindika kwenye foleni iliyotengwa.
2. **`xpc_connection_send_message_with_reply_sync`**: Kinyume chake, katika njia hii, ujumbe wa XPC unapokelewa na kusindika kwenye foleni ya sasa ya utekelezaji.

Tofauti hii ni muhimu kwa sababu inaruhusu uwezekano wa **pakiti za majibu kuchambuliwa kwa wakati mmoja na utekelezaji wa kiongozi wa tukio la XPC**. Hasa, wakati `_xpc_connection_set_creds` inatekeleza kufunga ili kulinda dhidi ya kuandika sehemu ya alama ya ukaguzi, haifanyi ulinzi huu kwa kitu cha uhusiano kizima. Kwa hivyo, hii inaunda udhaifu ambapo alama ya ukaguzi inaweza kubadilishwa wakati wa kipindi kati ya kuchambua kwa pakiti na utekelezaji wa kiongozi wa tukio lake.

Kuutumia udhaifu huu, usanidi ufuatao unahitajika:

- Huduma mbili za mach, zinazojulikana kama **`A`** na **`B`**, zote ambazo zinaweza kuanzisha uhusiano.
- Huduma **`A`** inapaswa kuwa na ukaguzi wa idhini kwa hatua maalum ambayo **`B`** tu inaweza kutekeleza (programu ya mtumiaji haiwezi).
- Huduma **`A`** inapaswa kutuma ujumbe ambao unatarajia majibu.
- Mtumiaji anaweza kutuma ujumbe kwa **`B`** ambao itajibu.

Mchakato wa kuutumia udhaifu huu unajumuisha hatua zifuatazo:

1. Subiri huduma **`A`** itume ujumbe ambao unatarajia majibu.
2. Badala ya kujibu moja kwa moja kwa **`A`**, bandari ya majibu inatekwa na kutumika kutuma ujumbe kwa huduma **`B`**.
3. Kisha, ujumbe unaohusisha hatua iliyokatazwa unatumwa, ukitarajia kwamba utasindika kwa wakati mmoja na majibu kutoka kwa **`B`**.

Hapa chini ni uwakilishi wa kielelezo wa senario ya shambulio iliyoelezwa:

![https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png](../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png)


<figure><img src="../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Matatizo ya Ugunduzi

- **Vikwazo katika Kupata Mifano**: Kutafuta mifano ya matumizi ya `xpc_connection_get_audit_token` ilikuwa changamoto, kwa njia za kistatiki na za kudumu.
- **Njia ya Utafiti**: Frida iliotumika kufunga kazi ya `xpc_connection_get_audit_token`, ikichuja wito usiotoka kwa wakurugenzi wa tukio. Walakini, njia hii ilikuwa imepunguzwa kwa mchakato uliofungwa na ilihitaji matumizi ya kazi hiyo.
- **Zana za Uchambuzi**: Zana kama IDA/Ghidra zilitumika kuchunguza huduma za mach zinazoweza kufikiwa, lakini mchakato ulikuwa wa muda mrefu, uliogumuza na wito unaohusisha hifadhi ya pamoja ya dyld.
- **Vikwazo vya Ufundi**: Jaribio la kuandika skripti ya uchambuzi kwa wito wa `xpc_connection_get_audit_token` kutoka kwa vitengo vya `dispatch_async` lilikwamishwa na ugumu wa kuchambua vitengo na mwingiliano na hifadhi ya pamoja ya dyld.

## Suluhisho <a href="#the-fix" id="the-fix"></a>

- **Masuala Yaliyoripotiwa**: Ripoti ilipelekwa kwa Apple ikielezea masuala ya jumla na maalum yaliyopatikana ndani ya `smd`.
- **Jibu la Apple**: Apple ilishughulikia suala hilo katika `smd` kwa kubadilisha `xpc_connection_get_audit_token` na `xpc_dictionary_get_audit_token`.
- **Asili ya Suluhisho**: Kazi ya `xpc_dictionary_get_audit_token` inachukuliwa kuwa salama kwani inapata alama ya ukaguzi moja kwa moja kutoka kwa ujumbe wa mach unaohusiana na ujumbe wa XPC uliopokelewa. Walakini, haipo katika API ya umma, kama vile `xpc_connection_get_audit_token`.
- **Ukosefu wa Suluhisho Pana**: Bado haijulikani kwa nini Apple haikutekeleza suluhisho pana zaidi, kama vile kutupa ujumbe ambao haufanani na alama ya ukaguzi iliyohifadhiwa ya uhusiano. Uwezekano wa mabadiliko halali ya alama ya ukaguzi katika hali fulani (kwa mfano, matumizi ya `setuid`) inaweza kuwa sababu.
- **Hali ya Sasa**: Tatizo linaendelea katika iOS 17 na macOS 14, likiwa changamoto kwa wale wanaotafuta kuligundua na kulielewa.
