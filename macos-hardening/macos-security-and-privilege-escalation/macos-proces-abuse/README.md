# Uvunjaji wa Mchakato wa macOS

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Mtaalam wa Timu Nyekundu ya AWS ya HackTricks)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi ya PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**Familia ya PEASS**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

## Uvunjaji wa Mchakato wa MacOS

MacOS, kama mfumo wa uendeshaji mwingine wowote, hutoa njia na mbinu mbalimbali za **mchakato kuingiliana, kuwasiliana, na kushiriki data**. Ingawa mbinu hizi ni muhimu kwa utendaji mzuri wa mfumo, pia zinaweza kutumiwa vibaya na wahalifu wa mtandao kufanya shughuli za uovu.

### Uingizaji wa Maktaba

Uingizaji wa Maktaba ni mbinu ambapo mshambuliaji **anawalazimisha mchakato kusoma maktaba yenye nia mbaya**. Mara baada ya kuingizwa, maktaba hiyo inaendesha katika muktadha wa mchakato wa lengo, ikimpa mshambuliaji idhini na ufikiaji sawa na mchakato huo.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### Kufunga Kazi

Kufunga Kazi ni mchakato wa **kukamata wito wa kazi** au ujumbe ndani ya nambari ya programu. Kwa kufunga kazi, mshambuliaji anaweza **kubadilisha tabia** ya mchakato, kuchunguza data nyeti, au hata kupata udhibiti wa mtiririko wa utekelezaji.

{% content-ref url="../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

### Mawasiliano kati ya Mchakato

Mawasiliano kati ya Mchakato (IPC) inahusu njia tofauti ambazo michakato tofauti **inashiriki na kubadilishana data**. Ingawa IPC ni muhimu kwa matumizi mengi halali, inaweza pia kutumiwa vibaya kwa kuvunja kizuizi cha mchakato, kuvuja habari nyeti, au kufanya vitendo visivyoruhusiwa.

{% content-ref url="../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Uingizaji wa Programu za Electron

Programu za Electron zilizoendeshwa na mazingira maalum ya env zinaweza kuwa na udhaifu wa uingizaji wa mchakato:

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### NIB Chafu

Faili za NIB **hutambua vipengele vya kiolesura cha mtumiaji (UI)** na mwingiliano wao ndani ya programu. Walakini, wanaweza **kutekeleza amri za kiholela** na **Gatekeeper haikatazi** programu iliyotekelezwa tayari kutoka kutekelezwa ikiwa faili ya NIB imebadilishwa. Kwa hivyo, wanaweza kutumiwa kufanya programu za kiholela kutekeleza amri za kiholela:

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Uingizaji wa Programu za Java

Inawezekana kutumia uwezo fulani wa Java (kama **`_JAVA_OPTS`** env variable) ili kufanya programu ya Java itekeleze **msimbo/amri za kiholela**.

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md](macos-java-apps-injection.md)
{% endcontent-ref %}

### Uingizaji wa Programu za .Net

Inawezekana kuingiza msimbo kwenye programu za .Net kwa **kutumia vibaya kazi ya kufuatilia ya .Net** (isiyolindwa na ulinzi wa macOS kama uimarishaji wa wakati wa utekelezaji).

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Uingizaji wa Perl

Angalia chaguzi tofauti za kufanya script ya Perl itekeleze msimbo wa kiholela:

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md](macos-perl-applications-injection.md)
{% endcontent-ref %}

### Uingizaji wa Ruby

Pia inawezekana kutumia mazingira ya env ya ruby kufanya script za kiholela zitekeleze msimbo wa kiholela:

{% content-ref url="macos-ruby-applications-injection.md" %}
[macos-ruby-applications-injection.md](macos-ruby-applications-injection.md)
{% endcontent-ref %}

### Uingizaji wa Python

Ikiwa mazingira ya env ya **`PYTHONINSPECT`** yameset, mchakato wa python utaingia kwenye cli ya python mara tu itakapomalizika. Pia inawezekana kutumia **`PYTHONSTARTUP`** kuonyesha script ya python itekelezwe mwanzoni mwa kikao cha mwingiliano.\
Hata hivyo, kumbuka kuwa script ya **`PYTHONSTARTUP`** haitatekelezwa wakati **`PYTHONINSPECT`** inaunda kikao cha mwingiliano.

Mazingira mengine ya env kama **`PYTHONPATH`** na **`PYTHONHOME`** pia yanaweza kuwa na manufaa kufanya amri ya python itekeleze msimbo wa kiholela.

Tafadhali kumbuka kuwa programu zilizopachikwa na **`pyinstaller`** hazitatumia mazingira haya ya kimazingira hata kama zinaendeshwa kwa kutumia python iliyowekwa.

{% hint style="danger" %}
Kwa ujumla, sikuweza kupata njia ya kufanya python itekeleze msimbo wa kiholela kwa kutumia vibaya mazingira ya env.\
Hata hivyo, watu wengi hufunga python kwa kutumia **Hombrew**, ambayo itainstall python katika eneo la **kuandika** kwa mtumiaji wa msimamizi wa chaguo-msingi. Unaweza kuchukua udhibiti wake kwa kitu kama:
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
{% endhint %}

## Uchunguzi

### Shield

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) ni programu huria ambayo inaweza **kuchunguza na kuzuia vitendo vya kuingiza mchakato**:

* Kwa kutumia **Mazingira ya Mazingira**: Itakuwa ikifuatilia uwepo wa mojawapo ya mazingira ya mazingira yafuatayo: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** na **`ELECTRON_RUN_AS_NODE`**
* Kwa kutumia wito wa **`task_for_pid`**: Ili kugundua wakati mchakato mmoja anataka kupata **kituo cha kazi cha mchakato mwingine** ambacho kinaruhusu kuingiza nambari katika mchakato.
* **Vigezo vya programu za Electron**: Mtu anaweza kutumia **`--inspect`**, **`--inspect-brk`** na **`--remote-debugging-port`** hoja ya mstari wa amri kuanza programu ya Electron katika hali ya kurekebisha, na hivyo kuingiza nambari ndani yake.
* Kwa kutumia **symlinks** au **hardlinks**: Kawaida unyanyasaji wa kawaida ni kuweka kiunga na **haki za mtumiaji wetu**, na **kuelekeza kwenye eneo lenye haki kubwa**. Uchunguzi ni rahisi sana kwa hardlink na symlinks. Ikiwa mchakato unaounda kiunga una **kiwango tofauti cha haki** kuliko faili ya lengo, tunatengeneza **onyo**. Kwa bahati mbaya katika kesi ya kuzuia symlinks haiwezekani, kwani hatuna habari juu ya marudio ya kiunga kabla ya kuundwa. Hii ni kizuizi cha mfumo wa EndpointSecuriy wa Apple.

### Wito uliofanywa na michakato mingine

Katika [**chapisho hili la blogu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) unaweza kupata jinsi inavyowezekana kutumia kazi ya **`task_name_for_pid`** kupata habari juu ya michakato mingine inayoingiza nambari katika mchakato na kisha kupata habari juu ya mchakato huo mwingine.

Tafadhali kumbuka kuwa ili kuita kazi hiyo unahitaji kuwa **uid sawa** na yule anayekimbia mchakato au **root** (na inarudi habari juu ya mchakato, sio njia ya kuingiza nambari).

## Marejeo

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa katika HackTricks** au **kupakua HackTricks katika PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
