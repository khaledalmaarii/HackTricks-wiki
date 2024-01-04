# Verificação do Processo de Conexão XPC no macOS

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Verificação do Processo de Conexão XPC

Quando uma conexão é estabelecida com um serviço XPC, o servidor verificará se a conexão é permitida. Estas são as verificações que normalmente são realizadas:

1. Verificar se o processo de conexão está assinado com um certificado **assinado pela Apple** (fornecido apenas pela Apple).
   * Se isso **não for verificado**, um atacante poderia criar um **certificado falso** para corresponder a qualquer outra verificação.
2. Verificar se o processo de conexão está assinado com o certificado da **organização**, (verificação do ID da equipe).
   * Se isso **não for verificado**, **qualquer certificado de desenvolvedor** da Apple pode ser usado para assinar e conectar-se ao serviço.
3. Verificar se o processo de conexão **contém um ID de pacote adequado**.
   * Se isso **não for verificado**, qualquer ferramenta **assinada pela mesma organização** poderia ser usada para interagir com o serviço XPC.
4. (4 ou 5) Verificar se o processo de conexão tem um **número de versão de software adequado**.
   * Se isso **não for verificado**, clientes antigos e inseguros, vulneráveis à injeção de processos, poderiam ser usados para se conectar ao serviço XPC mesmo com as outras verificações em vigor.
5. (4 ou 5) Verificar se o processo de conexão tem o runtime reforçado sem privilégios perigosos (como os que permitem carregar bibliotecas arbitrárias ou usar variáveis de ambiente DYLD)
   * Se isso **não for verificado**, o cliente pode ser **vulnerável à injeção de código**
6. Verificar se o processo de conexão tem um **privilégio** que permite a conexão com o serviço. Isso é aplicável para binários da Apple.
7. A **verificação** deve ser **baseada** no **token de auditoria do cliente** que se conecta **em vez** de seu ID de processo (**PID**), pois o primeiro previne **ataques de reutilização de PID**.
   * Desenvolvedores **raramente usam a chamada de API do token de auditoria** porque é **privada**, então a Apple poderia **mudar** a qualquer momento. Além disso, o uso de API privada não é permitido em aplicativos da Mac App Store.
   * Se o método **`processIdentifier`** for usado, ele pode ser vulnerável
   * **`xpc_dictionary_get_audit_token`** deve ser usado em vez de **`xpc_connection_get_audit_token`**, pois o último também pode ser [vulnerável em certas situações](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/).

### Ataques de Comunicação

Para mais informações sobre o ataque de reutilização de PID, confira:

{% content-ref url="macos-pid-reuse.md" %}
[macos-pid-reuse.md](macos-pid-reuse.md)
{% endcontent-ref %}

Para mais informações sobre o ataque **`xpc_connection_get_audit_token`**, confira:

{% content-ref url="macos-xpc_connection_get_audit_token-attack.md" %}
[macos-xpc\_connection\_get\_audit\_token-attack.md](macos-xpc\_connection\_get\_audit\_token-attack.md)
{% endcontent-ref %}

### Trustcache - Prevenção de Ataques de Downgrade

Trustcache é um método defensivo introduzido em máquinas com Apple Silicon que armazena um banco de dados de CDHSAH de binários da Apple, permitindo que apenas binários não modificados e autorizados sejam executados. Isso previne a execução de versões anteriores.

### Exemplos de Código

O servidor implementará essa **verificação** em uma função chamada **`shouldAcceptNewConnection`**.

{% code overflow="wrap" %}
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
{% endcode %}

O objeto NSXPCConnection possui uma propriedade **privada** **`auditToken`** (a que deveria ser usada, mas que pode mudar) e uma propriedade **pública** **`processIdentifier`** (a que não deveria ser usada).

O processo de conexão poderia ser verificado com algo como:

{% code overflow="wrap" %}
```objectivec
[...]
SecRequirementRef requirementRef = NULL;
NSString requirementString = @"anchor apple generic and identifier \"xyz.hacktricks.service\" and certificate leaf [subject.CN] = \"TEAMID\" and info [CFBundleShortVersionString] >= \"1.0\"";
/* Check:
- Signed by a cert signed by Apple
- Check the bundle ID
- Check the TEAMID of the signing cert
- Check the version used
*/

// Check the requirements with the PID (vulnerable)
SecRequirementCreateWithString(requirementString, kSecCSDefaultFlags, &requirementRef);
SecCodeCheckValidity(code, kSecCSDefaultFlags, requirementRef);

// Check the requirements wuing the auditToken (secure)
SecTaskRef taskRef = SecTaskCreateWithAuditToken(NULL, ((ExtendedNSXPCConnection*)newConnection).auditToken);
SecTaskValidateForRequirement(taskRef, (__bridge CFStringRef)(requirementString))
```
{% endcode %}

Se um desenvolvedor não quiser verificar a versão do cliente, ele poderia pelo menos verificar que o cliente não está vulnerável a injeção de processo:

{% code overflow="wrap" %}
```objectivec
[...]
CFDictionaryRef csInfo = NULL;
SecCodeCopySigningInformation(code, kSecCSDynamicInformation, &csInfo);
uint32_t csFlags = [((__bridge NSDictionary *)csInfo)[(__bridge NSString *)kSecCodeInfoStatus] intValue];
const uint32_t cs_hard = 0x100;        // don't load invalid page.
const uint32_t cs_kill = 0x200;        // Kill process if page is invalid
const uint32_t cs_restrict = 0x800;    // Prevent debugging
const uint32_t cs_require_lv = 0x2000; // Library Validation
const uint32_t cs_runtime = 0x10000;   // hardened runtime
if ((csFlags & (cs_hard | cs_require_lv)) {
return Yes; // Accept connection
}
```
<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
