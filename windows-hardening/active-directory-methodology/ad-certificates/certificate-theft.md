# Kradzież certyfikatów AD CS

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

**To jest krótkie podsumowanie rozdziałów o kradzieży z certyfikatów z niesamowitych badań ze strony [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**


## Co mogę zrobić z certyfikatem

Zanim sprawdzimy, jak kraść certyfikaty, oto kilka informacji na temat tego, do czego można wykorzystać certyfikat:
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
## Eksportowanie certyfikatów za pomocą interfejsów API kryptograficznego – KRAŚ1

W **sesji interaktywnego pulpitu**, wyodrębnienie certyfikatu użytkownika lub maszyny wraz z kluczem prywatnym jest łatwe, zwłaszcza jeśli **klucz prywatny jest eksportowalny**. Można to osiągnąć, przechodząc do certyfikatu w `certmgr.msc`, klikając prawym przyciskiem myszy i wybierając `Wszystkie zadania → Eksportuj`, aby wygenerować plik .pfx zabezpieczony hasłem.

W **programistycznym podejściu**, dostępne są narzędzia takie jak cmdlet PowerShell `ExportPfxCertificate` lub projekty takie jak [projekt C# CertStealer TheWovera](https://github.com/TheWover/CertStealer). Wykorzystują one **Microsoft CryptoAPI** (CAPI) lub Cryptography API: Next Generation (CNG), aby komunikować się ze składem certyfikatów. Te interfejsy API zapewniają szereg usług kryptograficznych, w tym te niezbędne do przechowywania i uwierzytelniania certyfikatów.

Jednak jeśli klucz prywatny jest ustawiony jako nieeksportowalny, zarówno CAPI, jak i CNG zazwyczaj blokują wyodrębnianie takich certyfikatów. Aby ominąć to ograniczenie, można użyć narzędzi takich jak **Mimikatz**. Mimikatz oferuje polecenia `crypto::capi` i `crypto::cng`, które umożliwiają łatanie odpowiednich interfejsów API, umożliwiając eksportowanie kluczy prywatnych. Konkretnie, `crypto::capi` łata CAPI w bieżącym procesie, podczas gdy `crypto::cng` kieruje się do pamięci **lsass.exe** w celu łatania.

## Kradzież certyfikatu użytkownika za pomocą DPAPI – KRAŚ2

Więcej informacji na temat DPAPI znajduje się w:

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

W systemie Windows **klucze prywatne certyfikatów są chronione przez DPAPI**. Ważne jest zrozumienie, że **miejsca przechowywania kluczy prywatnych użytkownika i maszyny** są różne, a struktury plików różnią się w zależności od użytego przez system operacyjny interfejsu API kryptograficznego. Narzędzie **SharpDPAPI** może automatycznie poradzić sobie z tymi różnicami podczas odszyfrowywania bloków DPAPI.

**Certyfikaty użytkownika** są głównie przechowywane w rejestrze pod `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, ale niektóre z nich można również znaleźć w katalogu `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. Odpowiednie **klucze prywatne** dla tych certyfikatów są zwykle przechowywane w `%APPDATA%\Microsoft\Crypto\RSA\User SID\` dla kluczy **CAPI** i `%APPDATA%\Microsoft\Crypto\Keys\` dla kluczy **CNG**.

Aby **wyodrębnić certyfikat i powiązany z nim klucz prywatny**, proces obejmuje:

1. **Wybranie docelowego certyfikatu** ze sklepu użytkownika i pobranie jego nazwy sklepu kluczy.
2. **Zlokalizowanie wymaganego klucza głównego DPAPI** do odszyfrowania odpowiadającego klucza prywatnego.
3. **Odszyfrowanie klucza prywatnego** przy użyciu klucza głównego DPAPI w postaci tekstu jawnego.

Do **uzyskania klucza głównego DPAPI w postaci tekstu jawnego** można użyć następujących podejść:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Aby zoptymalizować proces deszyfrowania plików klucza głównego i plików klucza prywatnego, polecenie `certificates` z narzędzia [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) okazuje się przydatne. Akceptuje ono argumenty `/pvk`, `/mkfile`, `/password` lub `{GUID}:KEY`, aby zdeszyfrować klucze prywatne i powiązane z nimi certyfikaty, generując w rezultacie plik `.pem`.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Kradzież certyfikatu maszynowego za pomocą DPAPI – THEFT3

Certyfikaty maszynowe przechowywane przez system Windows w rejestrze pod adresem `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates`, a także powiązane klucze prywatne znajdujące się w `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (dla CAPI) i `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (dla CNG) są szyfrowane za pomocą kluczy głównych DPAPI maszyny. Te klucze nie mogą być odszyfrowane za pomocą klucza zapasowego DPAPI domeny; zamiast tego wymagany jest **sekret LSA DPAPI_SYSTEM**, do którego dostęp ma tylko użytkownik SYSTEM.

Ręczne odszyfrowanie można osiągnąć, wykonując polecenie `lsadump::secrets` w narzędziu **Mimikatz**, aby wyodrębnić sekret LSA DPAPI_SYSTEM, a następnie użyć tego klucza do odszyfrowania kluczy głównych maszyny. Alternatywnie, można użyć polecenia `crypto::certificates /export /systemstore:LOCAL_MACHINE` w narzędziu Mimikatz po uprzednim łataniu CAPI/CNG, jak opisano wcześniej.

**SharpDPAPI** oferuje bardziej zautomatyzowane podejście za pomocą polecenia certificates. Po użyciu flagi `/machine` z uprawnieniami podniesionymi do poziomu SYSTEM, narzędzie to eskaluje uprawnienia, wyodrębnia sekret LSA DPAPI_SYSTEM, używa go do odszyfrowania kluczy głównych DPAPI maszyny, a następnie wykorzystuje te klucze w postaci tekstu jawnego jako tabelę poszukiwań do odszyfrowania kluczy prywatnych dowolnych certyfikatów maszynowych.


## Wyszukiwanie plików certyfikatów – THEFT4

Certyfikaty czasami są bezpośrednio znajdowane w systemie plików, na przykład w udostępnionych folderach lub folderze Pobrane. Najczęściej spotykanymi typami plików certyfikatów w środowiskach Windows są pliki `.pfx` i `.p12`. Rzadziej występują pliki o rozszerzeniach `.pkcs12` i `.pem`. Dodatkowe istotne rozszerzenia plików związanych z certyfikatami to:
- `.key` dla kluczy prywatnych,
- `.crt`/`.cer` dla samych certyfikatów,
- `.csr` dla żądań certyfikatów, które nie zawierają certyfikatów ani kluczy prywatnych,
- `.jks`/`.keystore`/`.keys` dla magazynów kluczy Javy, które mogą przechowywać certyfikaty wraz z kluczami prywatnymi używanymi przez aplikacje Javy.

Te pliki można wyszukiwać za pomocą PowerShell lub wiersza polecenia, szukając wymienionych rozszerzeń.

W przypadku znalezienia pliku certyfikatu PKCS#12, który jest chroniony hasłem, możliwe jest wyodrębnienie skrótu za pomocą narzędzia `pfx2john.py`, dostępnego na stronie [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). Następnie można użyć narzędzia JohnTheRipper, aby spróbować złamać hasło.
```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## Kradzież poświadczeń NTLM za pomocą PKINIT - THEFT5

Podany treść wyjaśnia metodę kradzieży poświadczeń NTLM za pomocą PKINIT, konkretnie poprzez metodę kradzieży oznaczoną jako THEFT5. Oto ponowne wyjaśnienie w stronie biernej, z anonimizacją treści i podsumowaniem tam, gdzie to możliwe:

Aby obsługiwać uwierzytelnianie NTLM [MS-NLMP] dla aplikacji, które nie umożliwiają uwierzytelniania Kerberos, KDC został zaprojektowany tak, aby zwracał jednokierunkową funkcję NTLM (OWF) użytkownika w ramach certyfikatu atrybutów uprawnień (PAC), konkretnie w buforze `PAC_CREDENTIAL_INFO`, gdy jest wykorzystywane PKCA. W rezultacie, jeśli konto uwierzytelnia się i zabezpiecza bilet TGT za pomocą PKINIT, dostarczany jest wbudowany mechanizm, który umożliwia bieżącemu hostowi wydobycie skrótu NTLM z TGT w celu obsługi protokołów uwierzytelniania dziedzictwa. Proces ten polega na odszyfrowaniu struktury `PAC_CREDENTIAL_DATA`, która jest w zasadzie zserializowanym opisem tekstu jawnego NTLM.

Wspomniano o narzędziu **Kekeo**, dostępnym pod adresem [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), które jest zdolne do żądania TGT zawierającego te konkretne dane, ułatwiając tym samym pozyskanie NTLM użytkownika. Polecenie używane w tym celu jest następujące:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
Dodatkowo, zauważono, że Kekeo może przetwarzać certyfikaty chronione kartą inteligentną, o ile można odzyskać PIN, z odniesieniem do [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). Ta sama funkcjonalność jest wskazana jako obsługiwana przez **Rubeus**, dostępny pod adresem [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

Ta wyjaśnienie obejmuje proces i narzędzia związane z kradzieżą poświadczeń NTLM za pomocą PKINIT, skupiając się na odzyskiwaniu skrótów NTLM poprzez TGT uzyskane za pomocą PKINIT oraz narzędziach ułatwiających ten proces.

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
