# Shadow Credentials

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

## Intro <a href="#3f17" id="3f17"></a>

**Check the original post for [all the information about this technique](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**

Como **resumo**: se você pode escrever na propriedade **msDS-KeyCredentialLink** de um usuário/computador, você pode recuperar o **hash NT desse objeto**.

No post, um método é delineado para configurar **credenciais de autenticação de chave pública-privada** para adquirir um **Ticket de Serviço** único que inclui o hash NTLM do alvo. Este processo envolve o NTLM_SUPPLEMENTAL_CREDENTIAL criptografado dentro do Certificado de Atributo de Privilégio (PAC), que pode ser descriptografado.

### Requirements

Para aplicar esta técnica, certas condições devem ser atendidas:
- É necessário um mínimo de um Controlador de Domínio Windows Server 2016.
- O Controlador de Domínio deve ter um certificado digital de autenticação de servidor instalado.
- O Active Directory deve estar no Nível Funcional do Windows Server 2016.
- É necessária uma conta com direitos delegados para modificar o atributo msDS-KeyCredentialLink do objeto alvo.

## Abuse

O abuso do Key Trust para objetos de computador abrange etapas além de obter um Ticket Granting Ticket (TGT) e o hash NTLM. As opções incluem:
1. Criar um **ticket prata RC4** para agir como usuários privilegiados no host pretendido.
2. Usar o TGT com **S4U2Self** para a impersonação de **usuários privilegiados**, necessitando alterações no Ticket de Serviço para adicionar uma classe de serviço ao nome do serviço.

Uma vantagem significativa do abuso do Key Trust é sua limitação à chave privada gerada pelo atacante, evitando a delegação para contas potencialmente vulneráveis e não exigindo a criação de uma conta de computador, o que poderia ser desafiador de remover.

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

É baseado no DSInternals, fornecendo uma interface C# para este ataque. Whisker e seu equivalente em Python, **pyWhisker**, permitem a manipulação do atributo `msDS-KeyCredentialLink` para obter controle sobre contas do Active Directory. Essas ferramentas suportam várias operações, como adicionar, listar, remover e limpar credenciais de chave do objeto alvo.

As funções do **Whisker** incluem:
- **Add**: Gera um par de chaves e adiciona uma credencial de chave.
- **List**: Exibe todas as entradas de credenciais de chave.
- **Remove**: Exclui uma credencial de chave especificada.
- **Clear**: Apaga todas as credenciais de chave, potencialmente interrompendo o uso legítimo do WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Ele estende a funcionalidade do Whisker para **sistemas baseados em UNIX**, aproveitando o Impacket e o PyDSInternals para capacidades de exploração abrangentes, incluindo listar, adicionar e remover KeyCredentials, bem como importar e exportar em formato JSON.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray tem como objetivo **explorar permissões GenericWrite/GenericAll que grupos de usuários amplos podem ter sobre objetos de domínio** para aplicar ShadowCredentials de forma ampla. Isso envolve fazer login no domínio, verificar o nível funcional do domínio, enumerar objetos de domínio e tentar adicionar KeyCredentials para aquisição de TGT e revelação de hash NT. Opções de limpeza e táticas de exploração recursiva aumentam sua utilidade.


## Referências

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
* [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}
