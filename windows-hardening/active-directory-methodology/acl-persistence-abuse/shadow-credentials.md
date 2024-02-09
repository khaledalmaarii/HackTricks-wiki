# Credenciais Shadow

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Você trabalha em uma **empresa de cibersegurança**? Quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Introdução <a href="#3f17" id="3f17"></a>

**Confira o post original para [todas as informações sobre essa técnica](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**

Em **resumo**: se você puder escrever na propriedade **msDS-KeyCredentialLink** de um usuário/computador, você pode recuperar o **hash NT desse objeto**.

No post, um método é delineado para configurar credenciais de autenticação **chave pública-privada** para adquirir um **Service Ticket** único que inclui o hash NTLM do alvo. Esse processo envolve o NTLM_SUPPLEMENTAL_CREDENTIAL criptografado dentro do Certificado de Atributo de Privilégio (PAC), que pode ser descriptografado.

### Requisitos

Para aplicar essa técnica, certas condições devem ser atendidas:
- É necessário no mínimo um Controlador de Domínio do Windows Server 2016.
- O Controlador de Domínio deve ter um certificado digital de autenticação de servidor instalado.
- O Active Directory deve estar no Nível Funcional do Windows Server 2016.
- Uma conta com direitos delegados para modificar o atributo msDS-KeyCredentialLink do objeto alvo é necessária.

## Abuso

O abuso do Key Trust para objetos de computador engloba etapas além da obtenção de um Ticket Granting Ticket (TGT) e do hash NTLM. As opções incluem:
1. Criar um **RC4 silver ticket** para agir como usuários privilegiados no host pretendido.
2. Usar o TGT com **S4U2Self** para a personificação de **usuários privilegiados**, exigindo alterações no Service Ticket para adicionar uma classe de serviço ao nome do serviço.

Uma vantagem significativa do abuso do Key Trust é sua limitação à chave privada gerada pelo atacante, evitando a delegação para contas potencialmente vulneráveis e não exigindo a criação de uma conta de computador, o que poderia ser desafiador de remover.

## Ferramentas

### [**Whisker**](https://github.com/eladshamir/Whisker)

Baseado no DSInternals, fornece uma interface C# para esse ataque. O Whisker e seu equivalente em Python, **pyWhisker**, permitem a manipulação do atributo `msDS-KeyCredentialLink` para obter controle sobre contas do Active Directory. Essas ferramentas suportam várias operações como adicionar, listar, remover e limpar credenciais-chave do objeto alvo.

As funções do **Whisker** incluem:
- **Adicionar**: Gera um par de chaves e adiciona uma credencial-chave.
- **Listar**: Exibe todas as entradas de credenciais-chave.
- **Remover**: Exclui uma credencial-chave especificada.
- **Limpar**: Apaga todas as credenciais-chave, potencialmente interrompendo o uso legítimo do WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Ele estende a funcionalidade do Whisker para sistemas baseados em **UNIX**, aproveitando o Impacket e PyDSInternals para capacidades abrangentes de exploração, incluindo listagem, adição e remoção de KeyCredentials, bem como importação e exportação em formato JSON.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

O ShadowSpray tem como objetivo **explorar permissões GenericWrite/GenericAll que grupos de usuários amplos podem ter sobre objetos de domínio** para aplicar amplamente as ShadowCredentials. Isso envolve fazer login no domínio, verificar o nível funcional do domínio, enumerar objetos de domínio e tentar adicionar KeyCredentials para aquisição de TGT e revelação de hash NT. Opções de limpeza e táticas de exploração recursiva aprimoram sua utilidade.


## Referências

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
* [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
