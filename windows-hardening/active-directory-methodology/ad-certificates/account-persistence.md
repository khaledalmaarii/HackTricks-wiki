# Persistência de Conta no AD CS

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Roubo de Credenciais de Usuário Ativo via Certificados – PERSIST1

Se o usuário tem permissão para solicitar um certificado que permite autenticação de domínio, um atacante poderia **solicitar** e **roubar** o mesmo para **manter** **persistência**.

O modelo **`User`** permite isso e vem por **padrão**. No entanto, pode estar desativado. Assim, [**Certify**](https://github.com/GhostPack/Certify) permite encontrar certificados válidos para persistir:
```
Certify.exe find /clientauth
```
Observe que um **certificado pode ser usado para autenticação** como aquele usuário enquanto o certificado estiver **válido**, **mesmo** se o usuário **alterar** sua **senha**.

A partir da **GUI**, é possível solicitar um certificado com `certmgr.msc` ou através da linha de comando com `certreq.exe`.

Usando [**Certify**](https://github.com/GhostPack/Certify), você pode executar:
```
Certify.exe request /ca:CA-SERVER\CA-NAME /template:TEMPLATE-NAME
```
O resultado será um bloco de texto formatado `.pem` contendo um **certificado** + **chave privada**
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Para **usar esse certificado**, pode-se então **fazer upload** do `.pfx` para um alvo e **usá-lo com** [**Rubeus**](https://github.com/GhostPack/Rubeus) para **solicitar um TGT** para o usuário inscrito, pelo tempo que o certificado for válido (a validade padrão é de 1 ano):
```bash
Rubeus.exe asktgt /user:harmj0y /certificate:C:\Temp\cert.pfx /password:CertPass!
```
{% hint style="warning" %}
Combinado com a técnica descrita na seção [**THEFT5**](certificate-theft.md#ntlm-credential-theft-via-pkinit-theft5), um atacante também pode **obter persistentemente o hash NTLM da conta**, que o atacante poderia usar para autenticar via **pass-the-hash** ou **crackear** para obter a **senha em texto simples**. \
Este é um método alternativo de **roubo de credenciais de longo prazo** que **não interage com o LSASS** e é possível a partir de um **contexto não elevado.**
{% endhint %}

## Persistência de Máquina via Certificados - PERSIST2

Se um modelo de certificado permitir **Domain Computers** como principais de inscrição, um atacante poderia **inscrever a conta de máquina de um sistema comprometido**. O modelo padrão **`Machine`** corresponde a todas essas características.

Se um **atacante elevar privilégios** em um sistema comprometido, o atacante pode usar a conta **SYSTEM** para se inscrever em modelos de certificado que concedem privilégios de inscrição para contas de máquina (mais informações em [**THEFT3**](certificate-theft.md#machine-certificate-theft-via-dpapi-theft3)).

Você pode usar [**Certify**](https://github.com/GhostPack/Certify) para coletar um certificado para a conta de máquina elevando automaticamente para SYSTEM com:
```bash
Certify.exe request /ca:dc.theshire.local/theshire-DC-CA /template:Machine /machine
```
Note que com acesso a um certificado de conta de máquina, o atacante pode então **autenticar-se no Kerberos** como a conta da máquina. Usando **S4U2Self**, um atacante pode então obter um **ticket de serviço Kerberos para qualquer serviço no host** (por exemplo, CIFS, HTTP, RPCSS, etc.) como qualquer usuário.

Em última análise, isso dá ao ataque um método de persistência de máquina.

## Persistência de Conta via Renovação de Certificado - PERSIST3

Modelos de certificado têm um **Período de Validade** que determina por quanto tempo um certificado emitido pode ser usado, bem como um **Período de Renovação** (geralmente 6 semanas). Esta é uma janela de **tempo antes** do certificado **expirar** onde uma **conta pode renová-lo** na autoridade emissora de certificados.

Se um atacante comprometer um certificado capaz de autenticação de domínio por roubo ou inscrição maliciosa, o atacante pode **autenticar-se no AD pelo período de validade do certificado**. No entanto, o atacante pode **renovar o certificado antes da expiração**. Isso pode funcionar como uma abordagem de **persistência estendida** que **evita que inscrições adicionais de tickets** sejam solicitadas, o que **pode deixar artefatos** no próprio servidor CA.

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) no github.

</details>
