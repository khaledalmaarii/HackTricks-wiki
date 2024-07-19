# AD CS Certificate Theft

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

**To jest małe podsumowanie rozdziałów dotyczących kradzieży z niesamowitych badań z [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**

## Co mogę zrobić z certyfikatem

Zanim sprawdzisz, jak ukraść certyfikaty, oto kilka informacji na temat tego, do czego certyfikat może być przydatny:
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
## Eksportowanie certyfikatów za pomocą Crypto APIs – THEFT1

W **interaktywnej sesji pulpitu**, ekstrakcja certyfikatu użytkownika lub maszyny, wraz z kluczem prywatnym, może być łatwo przeprowadzona, szczególnie jeśli **klucz prywatny jest eksportowalny**. Można to osiągnąć, przechodząc do certyfikatu w `certmgr.msc`, klikając prawym przyciskiem myszy i wybierając `Wszystkie zadania → Eksportuj`, aby wygenerować plik .pfx chroniony hasłem.

Dla **programatycznego podejścia**, dostępne są narzędzia takie jak cmdlet PowerShell `ExportPfxCertificate` lub projekty takie jak [projekt CertStealer C# TheWovera](https://github.com/TheWover/CertStealer). Wykorzystują one **Microsoft CryptoAPI** (CAPI) lub Cryptography API: Next Generation (CNG) do interakcji z magazynem certyfikatów. Te API oferują szereg usług kryptograficznych, w tym te niezbędne do przechowywania certyfikatów i uwierzytelniania.

Jednakże, jeśli klucz prywatny jest ustawiony jako nieeksportowalny, zarówno CAPI, jak i CNG normalnie zablokują ekstrakcję takich certyfikatów. Aby obejść to ograniczenie, można wykorzystać narzędzia takie jak **Mimikatz**. Mimikatz oferuje polecenia `crypto::capi` i `crypto::cng` do patchowania odpowiednich API, co pozwala na eksport kluczy prywatnych. Konkretnie, `crypto::capi` patchuje CAPI w bieżącym procesie, podczas gdy `crypto::cng` celuje w pamięć **lsass.exe** do patchowania.

## Kradzież certyfikatu użytkownika za pomocą DPAPI – THEFT2

Więcej informacji o DPAPI w:

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

W systemie Windows, **klucze prywatne certyfikatów są chronione przez DPAPI**. Ważne jest, aby rozpoznać, że **lokalizacje przechowywania kluczy prywatnych użytkownika i maszyny** są różne, a struktury plików różnią się w zależności od używanego przez system operacyjny API kryptograficznego. **SharpDPAPI** to narzędzie, które może automatycznie poruszać się po tych różnicach podczas deszyfrowania blobów DPAPI.

**Certyfikaty użytkowników** są głównie przechowywane w rejestrze pod `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, ale niektóre można również znaleźć w katalogu `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. Odpowiednie **klucze prywatne** dla tych certyfikatów są zazwyczaj przechowywane w `%APPDATA%\Microsoft\Crypto\RSA\User SID\` dla kluczy **CAPI** i `%APPDATA%\Microsoft\Crypto\Keys\` dla kluczy **CNG**.

Aby **wyekstrahować certyfikat i jego powiązany klucz prywatny**, proces obejmuje:

1. **Wybór docelowego certyfikatu** z magazynu użytkownika i pobranie jego nazwy magazynu kluczy.
2. **Zlokalizowanie wymaganego klucza głównego DPAPI** do deszyfrowania odpowiadającego klucza prywatnego.
3. **Deszyfrowanie klucza prywatnego** przy użyciu jawnego klucza głównego DPAPI.

Aby **zdobyć jawny klucz główny DPAPI**, można wykorzystać następujące podejścia:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Aby uprościć deszyfrowanie plików masterkey i plików kluczy prywatnych, polecenie `certificates` z [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) okazuje się przydatne. Akceptuje argumenty `/pvk`, `/mkfile`, `/password` lub `{GUID}:KEY` do deszyfrowania kluczy prywatnych i powiązanych certyfikatów, a następnie generuje plik `.pem`.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Kradzież certyfikatów maszynowych za pomocą DPAPI – THEFT3

Certyfikaty maszynowe przechowywane przez Windows w rejestrze pod `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` oraz powiązane klucze prywatne znajdujące się w `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (dla CAPI) i `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (dla CNG) są szyfrowane za pomocą głównych kluczy DPAPI maszyny. Klucze te nie mogą być odszyfrowane za pomocą zapasowego klucza DPAPI domeny; zamiast tego wymagany jest **sekret LSA DPAPI_SYSTEM**, do którego dostęp ma tylko użytkownik SYSTEM.

Ręczne odszyfrowanie można osiągnąć, wykonując polecenie `lsadump::secrets` w **Mimikatz**, aby wyodrębnić sekret LSA DPAPI_SYSTEM, a następnie używając tego klucza do odszyfrowania głównych kluczy maszyny. Alternatywnie, polecenie `crypto::certificates /export /systemstore:LOCAL_MACHINE` w Mimikatz może być użyte po załataniu CAPI/CNG, jak wcześniej opisano.

**SharpDPAPI** oferuje bardziej zautomatyzowane podejście za pomocą swojego polecenia certyfikatów. Gdy użyty jest znacznik `/machine` z podwyższonymi uprawnieniami, eskaluje do SYSTEM, zrzuca sekret LSA DPAPI_SYSTEM, używa go do odszyfrowania głównych kluczy DPAPI maszyny, a następnie wykorzystuje te klucze w postaci jawnej jako tabelę wyszukiwania do odszyfrowania wszelkich kluczy prywatnych certyfikatów maszynowych.

## Znajdowanie plików certyfikatów – THEFT4

Certyfikaty czasami znajdują się bezpośrednio w systemie plików, na przykład w udostępnionych folderach lub folderze Pobrane. Najczęściej spotykane typy plików certyfikatów skierowanych do środowisk Windows to pliki `.pfx` i `.p12`. Choć rzadziej, pojawiają się również pliki z rozszerzeniami `.pkcs12` i `.pem`. Dodatkowe istotne rozszerzenia plików związanych z certyfikatami to:
- `.key` dla kluczy prywatnych,
- `.crt`/`.cer` dla certyfikatów tylko,
- `.csr` dla żądań podpisania certyfikatu, które nie zawierają certyfikatów ani kluczy prywatnych,
- `.jks`/`.keystore`/`.keys` dla Java Keystores, które mogą zawierać certyfikaty wraz z kluczami prywatnymi wykorzystywanymi przez aplikacje Java.

Pliki te można wyszukiwać za pomocą PowerShell lub wiersza poleceń, szukając wymienionych rozszerzeń.

W przypadkach, gdy znaleziony zostanie plik certyfikatu PKCS#12 i jest on chroniony hasłem, możliwe jest wyodrębnienie hasha za pomocą `pfx2john.py`, dostępnego na [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). Następnie można użyć JohnTheRipper, aby spróbować złamać hasło.
```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## NTLM Credential Theft via PKINIT – THEFT5

Zawarte treści wyjaśniają metodę kradzieży poświadczeń NTLM za pomocą PKINIT, szczególnie poprzez metodę kradzieży oznaczoną jako THEFT5. Oto ponowne wyjaśnienie w stronie biernej, z treścią zanonimizowaną i podsumowaną tam, gdzie to możliwe:

Aby wspierać uwierzytelnianie NTLM [MS-NLMP] dla aplikacji, które nie umożliwiają uwierzytelniania Kerberos, KDC jest zaprojektowany tak, aby zwracać jedną funkcję NTLM (OWF) użytkownika w certyfikacie atrybutu uprawnień (PAC), szczególnie w buforze `PAC_CREDENTIAL_INFO`, gdy wykorzystywane jest PKCA. W związku z tym, jeśli konto uwierzytelni się i zabezpieczy bilet przyznawania biletów (TGT) za pomocą PKINIT, wbudowany mechanizm umożliwia bieżącemu hostowi wydobycie hasha NTLM z TGT, aby wspierać starsze protokoły uwierzytelniania. Proces ten obejmuje deszyfrowanie struktury `PAC_CREDENTIAL_DATA`, która jest zasadniczo zserializowanym przedstawieniem NTLM w postaci jawnej.

Narzędzie **Kekeo**, dostępne pod adresem [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), jest wspomniane jako zdolne do żądania TGT zawierającego te konkretne dane, co ułatwia odzyskanie NTLM użytkownika. Komenda używana w tym celu jest następująca:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
Dodatkowo zauważono, że Kekeo może przetwarzać certyfikaty chronione kartą inteligentną, pod warunkiem, że pin może być odzyskany, z odniesieniem do [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). Ta sama funkcjonalność jest wskazana jako wspierana przez **Rubeus**, dostępny pod adresem [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

To wyjaśnienie podsumowuje proces i narzędzia zaangażowane w kradzież poświadczeń NTLM za pomocą PKINIT, koncentrując się na odzyskiwaniu skrótów NTLM poprzez TGT uzyskane za pomocą PKINIT oraz narzędziach, które ułatwiają ten proces.

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
