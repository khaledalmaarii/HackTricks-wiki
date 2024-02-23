# Uvunjaji wa Mchakato wa macOS

<details>

<summary><strong>Jifunze kuhusu kuvamia AWS kutoka mwanzo hadi mtaalamu na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalamu wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za kuvamia kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Uvunjaji wa Mchakato wa MacOS

MacOS, kama mfumo mwingine wowote wa uendeshaji, hutoa njia na mbinu mbalimbali za **mchakato kuingiliana, kuwasiliana, na kushiriki data**. Ingawa njia hizi ni muhimu kwa utendaji mzuri wa mfumo, zinaweza kutumiwa vibaya na wahalifu wa mtandao kufanya **shughuli za uovu**.

### Kuingiza Maktaba

Kuingiza Maktaba ni mbinu ambapo mshambuliaji **anailazimisha mchakato kusoma maktaba mbaya**. Mara ilipoingizwa, maktaba hiyo inaendeshwa katika muktadha wa mchakato lengwa, ikimpa mshambuliaji idhini na ufikiaji sawa na mchakato.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### Kufunga Kazi

Kufunga Kazi inahusisha **kukamata simu za kazi** au ujumbe ndani ya nambari ya programu. Kwa kufunga kazi, mshambuliaji anaweza **kurekebisha tabia** ya mchakato, kuchunguza data nyeti, au hata kupata udhibiti wa mtiririko wa utekelezaji.

{% content-ref url="../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

### Mawasiliano kati ya Mchakato

Mawasiliano kati ya Mchakato (IPC) inahusu njia tofauti ambazo mchakato tofauti **hushiriki na kubadilishana data**. Ingawa IPC ni muhimu kwa programu nyingi halali, inaweza pia kutumiwa vibaya kwa kukiuka kizuizi cha mchakato, kuvuja kwa habari nyeti, au kufanya vitendo visivyoruhusiwa.

{% content-ref url="../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Kuingiza Programu za Electron

Programu za Electron zilizoendeshwa na mazingira maalum zinaweza kuwa na hatari ya kuingiza mchakato:

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### Kuingiza Chromium

Inawezekana kutumia bendera `--load-extension` na `--use-fake-ui-for-media-stream` kufanya **mashambulizi ya mtu katika kivinjari** kuruhusu kuiba pigo la kibodi, trafiki, vidakuzi, kuingiza skripti kwenye kurasa...:

{% content-ref url="macos-chromium-injection.md" %}
[macos-chromium-injection.md](macos-chromium-injection.md)
{% endcontent-ref %}

### NIB Chafu

Faili za NIB **hufafanua vipengele vya interface ya mtumiaji (UI)** na mwingiliano wao ndani ya programu. Walakini, wanaweza **kutekeleza amri za kupindukia** na **Gatekeeper haisimamishi** programu iliyotekelezwa tayari isitekelezwe ikiwa faili ya **NIB imebadilishwa**. Kwa hivyo, zinaweza kutumika kufanya programu za kupindukia zitekeleze amri za kupindukia:

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Kuingiza Programu za Java

Inawezekana kutumia uwezo fulani wa java (kama **`_JAVA_OPTS`** env variable) kufanya programu ya java itekeleze **mimba ya nambari/amri**.

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md](macos-java-apps-injection.md)
{% endcontent-ref %}

### Kuingiza Programu za .Net

Inawezekana kuingiza nambari kwenye programu za .Net kwa **kutumia vibaya kazi ya kufuatilia ya .Net** (isilindwe na ulinzi wa macOS kama vile ukali wa wakati wa utekelezaji).

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Kuingiza Perl

Angalia chaguzi tofauti za kufanya skripti ya Perl itekeleze nambari ya kupindukia katika:

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md](macos-perl-applications-injection.md)
{% endcontent-ref %}

### Kuingiza Ruby

Pia inawezekana kutumia mazingira ya ruby kufanya skripti za kupindukia zitekeleze nambari ya kupindukia:

{% content-ref url="macos-ruby-applications-injection.md" %}
[macos-ruby-applications-injection.md](macos-ruby-applications-injection.md)
{% endcontent-ref %}

### Kuingiza Python

Ikiwa mazingira ya **`PYTHONINSPECT`** yanawekwa, mchakato wa python utaingia kwenye cli ya python mara tu itakapomaliza. Pia inawezekana kutumia **`PYTHONSTARTUP`** kuonyesha skripti ya python itekelezwe mwanzoni mwa kikao cha mwingiliano.\
Walakini, kumbuka kwamba skripti ya **`PYTHONSTARTUP`** haitatekelezwa wakati **`PYTHONINSPECT`** inaunda kikao cha mwingiliano.

Mazingira mengine kama **`PYTHONPATH`** na **`PYTHONHOME`** pia yanaweza kuwa na manufaa kufanya amri ya python itekeleze nambari ya kupindukia.

Tambua kwamba programu zilizopangwa na **`pyinstaller`** hazitatumia mazingira haya hata kama zinaendeshwa kwa kutumia python iliyowekwa.

{% hint style="danger" %}
Kwa ujumla sikuweza kupata njia ya kufanya python itekeleze nambari ya kupindukia kwa kutumia mazingira ya mazingira.\
Walakini, wengi wa watu hufunga pyhton kwa kutumia **Hombrew**, ambayo itaiweka pyhton katika **eneo linaloweza kuandikwa** kwa mtumiaji wa kawaida wa msimamizi. Unaweza kuiba hiyo kwa kitu kama:
```bash
mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
cat > /opt/homebrew/bin/python3 <<EOF
#!/bin/bash
# Extra hijack code
/opt/homebrew/bin/python3.old "$@"
EOF
chmod +x /opt/homebrew/bin/python3
```
Hata **root** atakimbia nambari hii wakati wa kukimbia python.

## Uchunguzi

### Kinga

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) ni programu huru ambayo inaweza **kugundua na kuzuia vitendo vya kuingiza mchakato**:

* Kutumia **Mazingira ya Mazingira**: Itaangalia uwepo wa mojawapo ya mazingira ya mazingira yafuatayo: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** na **`ELECTRON_RUN_AS_NODE`**
* Kutumia simu za **`task_for_pid`**: Ili kugundua wakati mchakato mmoja anataka kupata **bandari ya kazi ya mwingine** ambayo inaruhusu kuingiza nambari katika mchakato.
* **Parameta za programu za Electron**: Mtu anaweza kutumia **`--inspect`**, **`--inspect-brk`** na **`--remote-debugging-port`** hoja ya mstari wa amri kuanza programu ya Electron katika hali ya kutatua matatizo, na hivyo kuingiza nambari ndani yake.
* Kutumia **viungo vya alama** au **viungo vya ngumu**: Kawaida unyanyasaji wa kawaida ni kuweka kiungo na **ruhusa zetu za mtumiaji**, na **kuielekeza kwenye eneo lenye ruhusa kubwa**. Uchunguzi ni rahisi sana kwa viungo vya ngumu na viungo vya alama. Ikiwa mchakato unaounda kiungo una **kiwango tofauti cha ruhusa** kuliko faili ya lengo, tunatuma **onyo**. Kwa bahati mbaya katika kesi ya viungo vya alama, kuzuia haiwezekani, kwani hatuna habari kuhusu marudio ya kiungo kabla ya uumbaji. Hii ni kizuizi cha mfumo wa EndpointSecuriy wa Apple.

### Simu zilizofanywa na michakato mingine

Katika [**chapisho hili la blogi**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) unaweza kupata jinsi inavyowezekana kutumia kazi ya **`task_name_for_pid`** kupata habari kuhusu **michakato inayoingiza nambari katika mchakato** mwingine na kisha kupata habari kuhusu mchakato huo.

Tafadhali kumbuka kwamba ili kuita kazi hiyo unahitaji kuwa **uid sawa** na yule anayekimbia mchakato au **root** (na inarudi habari kuhusu mchakato, si njia ya kuingiza nambari).

## Marejeo

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

<details>

<summary><strong>Jifunze kuhusu udukuzi wa AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa PDF** Angalia [**MIPANGO YA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**bidhaa rasmi za PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au kikundi cha [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Shiriki mbinu zako za udukuzi kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
