# Wizi wa Vyeti vya AD CS

<details>

<summary><strong>Jifunze kuhusu kuhack AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) ya kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kuhack kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

**Hii ni muhtasari mdogo wa sura za Wizi kutoka kwenye utafiti mzuri kutoka [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**


## Ninaweza kufanya nini na cheti

Kabla ya kuangalia jinsi ya kuiba vyeti, hapa kuna habari kuhusu jinsi ya kugundua matumizi ya cheti:
```powershell
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```
## Uchukuzi wa Vyeti kwa Kutumia API za Crypto - WIVU1

Katika kikao cha **desktop cha kuingiliana**, kuchukua cheti cha mtumiaji au mashine, pamoja na ufunguo wa kibinafsi, inaweza kufanywa kwa urahisi, haswa ikiwa **ufunguo wa kibinafsi unaweza kusafirishwa**. Hii inaweza kufanikiwa kwa kuelekea kwenye cheti katika `certmgr.msc`, kubonyeza kulia juu yake, na kuchagua `All Tasks → Export` ili kuzalisha faili ya .pfx iliyo na ulinzi wa nenosiri.

Kwa **njia ya programu**, zana kama cmdlet ya PowerShell `ExportPfxCertificate` au miradi kama [Miradi ya C# ya CertStealer ya TheWover](https://github.com/TheWover/CertStealer) inapatikana. Hizi hutumia **Microsoft CryptoAPI** (CAPI) au Cryptography API: Kizazi Kijacho (CNG) kuingiliana na hifadhi ya vyeti. API hizi hutoa huduma mbalimbali za kriptografia, ikiwa ni pamoja na zile zinazohitajika kwa uhifadhi na uwakilishi wa vyeti.

Hata hivyo, ikiwa ufunguo wa kibinafsi umewekwa kama usiosafirishwa, CAPI na CNG kwa kawaida zitazuia uchukuzi wa vyeti kama hivyo. Ili kuepuka kizuizi hiki, zana kama **Mimikatz** zinaweza kutumika. Mimikatz inatoa amri za `crypto::capi` na `crypto::cng` kufanya marekebisho kwenye API husika, kuruhusu uchukuzi wa ufunguo wa kibinafsi. Kwa usahihi, `crypto::capi` inafanya marekebisho kwenye CAPI ndani ya mchakato wa sasa, wakati `crypto::cng` inalenga kumbukumbu ya **lsass.exe** kwa ajili ya marekebisho.

## Wizi wa Cheti cha Mtumiaji kupitia DPAPI - WIVU2

Maelezo zaidi kuhusu DPAPI katika:

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

Katika Windows, **ufunguo wa kibinafsi wa vyeti unalindwa na DPAPI**. Ni muhimu kutambua kuwa **eneo la kuhifadhi ufunguo wa kibinafsi wa mtumiaji na mashine** ni tofauti, na muundo wa faili unatofautiana kulingana na API ya kriptografia inayotumiwa na mfumo wa uendeshaji. **SharpDPAPI** ni zana ambayo inaweza kusafiri tofauti hizi kiotomatiki wakati wa kufuta blobs za DPAPI.

**Vyeti vya mtumiaji** kwa kawaida hufanywa katika usajili chini ya `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, lakini baadhi yanaweza kupatikana pia katika saraka `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. **Ufunguo wa kibinafsi** unaofanana na vyeti hivi kwa kawaida huhifadhiwa katika `%APPDATA%\Microsoft\Crypto\RSA\User SID\` kwa ufunguo wa **CAPI** na `%APPDATA%\Microsoft\Crypto\Keys\` kwa ufunguo wa **CNG**.

Kwa **kuchukua cheti na ufunguo wake wa kibinafsi unaohusiana**, mchakato unahusisha:

1. **Kuchagua cheti lengwa** kutoka kwenye hifadhi ya mtumiaji na kupata jina la hifadhi ya ufunguo wake.
2. **Kutafuta DPAPI masterkey inayohitajika** ili kuweza kufuta ufunguo wa kibinafsi unaohusiana.
3. **Kufuta ufunguo wa kibinafsi** kwa kutumia DPAPI masterkey ya maandishi wazi.

Kwa **kupata DPAPI masterkey ya maandishi wazi**, njia zifuatazo zinaweza kutumika:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Ili kuongeza ufanisi wa kufichua faili za masterkey na faili za ufunguo binafsi, amri ya `certificates` kutoka [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) ina faida. Inakubali `/pvk`, `/mkfile`, `/password`, au `{GUID}:KEY` kama hoja za kufichua ufunguo binafsi na vyeti vilivyohusishwa, na hatimaye kuzalisha faili ya `.pem`.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Wizi wa Cheti cha Mashine kupitia DPAPI - THEFT3

Vyeti vya mashine vilivyohifadhiwa na Windows kwenye usajili kwenye `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` na funguo binafsi zinazohusiana zilizopo kwenye `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (kwa CAPI) na `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (kwa CNG) zimefichwa kwa kutumia funguo za DPAPI za mashine. Funguo hizi haziwezi kufichuliwa kwa kutumia funguo za DPAPI za nakala za akiba za kikoa; badala yake, inahitajika **siri ya DPAPI_SYSTEM LSA**, ambayo inaweza kufikiwa tu na mtumiaji wa SYSTEM.

Ufichuzi wa mwongozo unaweza kufanikiwa kwa kutekeleza amri ya `lsadump::secrets` katika **Mimikatz** ili kuchimbua siri ya DPAPI_SYSTEM LSA, na kisha kutumia funguo hii kufichua funguo za msingi za mashine. Kwa njia mbadala, amri ya `crypto::certificates /export /systemstore:LOCAL_MACHINE` ya Mimikatz inaweza kutumika baada ya kufanya marekebisho kwenye CAPI/CNG kama ilivyoelezwa hapo awali.

**SharpDPAPI** inatoa njia iliyorahisishwa zaidi na amri yake ya vyeti. Wakati bendera ya `/machine` inatumika na ruhusa zilizoinuliwa, inapanda hadi SYSTEM, inachukua siri ya DPAPI_SYSTEM LSA, inaitumia kufichua funguo za msingi za DPAPI za mashine, na kisha inatumia funguo hizi za maandishi wazi kama meza ya kutafuta kufichua funguo binafsi za vyeti vya mashine.

## Kupata Faili za Cheti - THEFT4

Vyeti mara nyingi hupatikana moja kwa moja kwenye mfumo wa faili, kama vile kwenye sehemu za kugawana faili au folda ya Upakuaji. Aina za faili za cheti zinazokutwa mara kwa mara kwenye mazingira ya Windows ni faili za `.pfx` na `.p12`. Ingawa kwa nadra, faili zenye ugani wa `.pkcs12` na `.pem` pia zinatokea. Ugani wa faili zinazohusiana na vyeti unajumuisha:
- `.key` kwa funguo binafsi,
- `.crt`/`.cer` kwa vyeti pekee,
- `.csr` kwa Maombi ya Kusaini Cheti, ambayo hayana vyeti wala funguo binafsi,
- `.jks`/`.keystore`/`.keys` kwa Hifadhi za Java, ambazo zinaweza kushikilia vyeti pamoja na funguo binafsi zinazotumiwa na programu za Java.

Faili hizi zinaweza kutafutwa kwa kutumia PowerShell au dirisha la amri kwa kutafuta ugani uliotajwa.

Katika kesi ambapo faili ya cheti ya PKCS#12 inapatikana na imekingwa na nenosiri, inawezekana kuchimbua hash kwa kutumia `pfx2john.py`, inayopatikana kwenye [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). Kwa kuongezea, JohnTheRipper inaweza kutumika kujaribu kuvunja nenosiri.
```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## Wizi wa Vitambulisho vya NTLM kupitia PKINIT - WIZI5

Yaliyomo yaliyotolewa yanafafanua njia ya wizi wa vitambulisho vya NTLM kupitia PKINIT, haswa kupitia njia ya wizi inayoitwa WIZI5. Hapa kuna ufafanuzi tena kwa mtindo wa sauti ya kisitiri, na yaliyomo yamefichwa na kusisitizwa pale inapofaa:

Kuunga mkono uwakilishi wa NTLM [MS-NLMP] kwa programu ambazo haziruhusu uwakilishi wa Kerberos, KDC imeundwa kurudisha kazi ya njia moja ya NTLM ya mtumiaji (OWF) ndani ya cheti cha sifa cha haki (PAC), haswa katika kifurushi cha `PAC_CREDENTIAL_INFO`, wakati PKCA inatumika. Kwa hivyo, ikiwa akaunti inathibitisha na kusimamia Tiketi ya Kutoa Tiketi (TGT) kupitia PKINIT, kuna utaratibu uliopo ambao unawezesha mwenyeji wa sasa kuchukua hash ya NTLM kutoka kwa TGT ili kudumisha itifaki za uwakilishi za zamani. Mchakato huu unahusisha kufichua muundo wa `PAC_CREDENTIAL_DATA`, ambao kimsingi ni taswira iliyosimbwa ya maandishi wazi ya NTLM.

Zana ya **Kekeo**, inayopatikana kwenye [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), inatajwa kuwa na uwezo wa kuomba TGT inayojumuisha data maalum hii, hivyo kurahisisha upatikanaji wa NTLM ya mtumiaji. Amri inayotumiwa kwa kusudi hili ni kama ifuatavyo:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
Kwa kuongezea, imebainika kuwa Kekeo inaweza kusindika vyeti vilivyolindwa na kadi za akili, ikitoa kwamba pin inaweza kupatikana, kwa kurejelea [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). Uwezo sawa unadaiwa kusaidiwa na **Rubeus**, inapatikana kwenye [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

Maelezo haya yanajumuisha mchakato na zana zinazohusika katika wizi wa kitambulisho cha NTLM kupitia PKINIT, kuzingatia upatikanaji wa hash za NTLM kupitia TGT iliyopatikana kwa kutumia PKINIT, na programu zinazowezesha mchakato huu.

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka mwanzo hadi kuwa bingwa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikitangazwa kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PR kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
