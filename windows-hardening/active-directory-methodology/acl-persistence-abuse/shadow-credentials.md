# Credenciais Shadow

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) **grupo Discord** ou ao **grupo telegram** ou **siga-me** no **Twitter** **🐦** [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Introdução <a href="#3f17" id="3f17"></a>

Verifique a postagem original para [**todas as informações sobre essa técnica**](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).

Em **resumo**: se você puder escrever na propriedade **msDS-KeyCredentialLink** de um usuário/computador, você pode recuperar o **hash NT desse objeto**.

Isso ocorre porque você poderá definir **credenciais de autenticação de chave pública-privada** para o objeto e usá-las para obter um **Ticket de Serviço especial que contém seu hash NT** dentro do Certificado de Atributo de Privilégio (PAC) em uma entidade NTLM\_SUPPLEMENTAL\_CREDENTIAL criptografada que você pode descriptografar.

### Requisitos <a href="#2de4" id="2de4"></a>

Essa técnica requer o seguinte:

* Pelo menos um Controlador de Domínio do Windows Server 2016.
* Um certificado digital para Autenticação de Servidor instalado no Controlador de Domínio.
* Nível Funcional do Windows Server 2016 no Active Directory.
* Comprometer uma conta com direitos delegados para escrever no atributo msDS-KeyCredentialLink do objeto alvo.

## Abuso

Abusar do Key Trust para objetos de computador requer etapas adicionais após obter um TGT e o hash NT da conta. Geralmente, existem duas opções:

1. Forjar um **ticket silver RC4** para se passar por usuários privilegiados no host correspondente.
2. Usar o TGT para chamar **S4U2Self** para se passar por **usuários privilegiados** no host correspondente. Esta opção requer modificar o Ticket de Serviço obtido para incluir uma classe de serviço no nome do serviço.

O abuso do Key Trust tem o benefício adicional de que não delega acesso a outra conta que poderia ser comprometida — ele é **restrito à chave privada gerada pelo atacante**. Além disso, não requer a criação de uma conta de computador que pode ser difícil de limpar até que a escalada de privilégios seja alcançada.

Whisker

Junto com esta postagem, estou lançando uma ferramenta chamada " [Whisker](https://github.com/eladshamir/Whisker) ". Com base no código do DSInternals de Michael, o Whisker fornece um wrapper C# para realizar esse ataque em engajamentos. O Whisker atualiza o objeto alvo usando LDAP, enquanto o DSInternals permite atualizar objetos usando tanto LDAP quanto RPC com o Serviço de Replicação de Diretório (DRS) Remote Protocol.

[Whisker](https://github.com/eladshamir/Whisker) possui quatro funções:

* Add — Esta função gera um par de chaves pública-privada e adiciona uma nova credencial de chave ao objeto alvo como se o usuário tivesse se inscrito no WHfB a partir de um novo dispositivo.
* List — Esta função lista todas as entradas do atributo msDS-KeyCredentialLink do objeto alvo.
* Remove — Esta função remove uma credencial de chave do objeto alvo especificada por um GUID de DeviceID.
* Clear — Esta função remove todos os valores do atributo msDS-KeyCredentialLink do objeto alvo. Se o objeto alvo estiver usando legitimamente o WHfB, ele será quebrado.

## [Whisker](https://github.com/eladshamir/Whisker) <a href="#7e2e" id="7e2e"></a>

Whisker é uma ferramenta C# para assumir o controle de contas de usuário e computador do Active Directory manipulando seu atributo `msDS-KeyCredentialLink`, adicionando efetivamente "Credenciais Shadow" à conta de destino.

[**Whisker**](https://github.com/eladshamir/Whisker) possui quatro funções:

* **Add** — Esta função gera um par de chaves pública-privada e adiciona uma nova credencial de chave ao objeto alvo como se o usuário tivesse se inscrito no WHfB a partir de um novo dispositivo.
* **List** — Esta função lista todas as entradas do atributo msDS-KeyCredentialLink do objeto alvo.
* **Remove** — Esta função remove uma credencial de chave do objeto alvo especificada por um GUID de DeviceID.
* **Clear** — Esta função remove todos os valores do atributo msDS-KeyCredentialLink do objeto alvo. Se o objeto alvo estiver usando legitimamente o WHfB, ele será quebrado.

### Add

Adicione um novo valor ao atributo **`msDS-KeyCredentialLink`** de um objeto alvo:

* `/target:<samAccountName>`: Obrigatório. Define o nome do alvo. Objetos de computador devem terminar com um sinal '$'.
* `/domain:<FQDN>`: Opcional. Define o Nome de Domínio Completo (FQDN) do alvo. Se não fornecido, tentará resolver o FQDN do usuário atual.
* `/dc:<IP/HOSTNAME>`: Opcional. Define o Controlador de Domínio (DC) de destino. Se não fornecido, tentará direcionar o Controlador de Domínio Primário (PDC).
* `/path:<PATH>`: Opcional. Define o caminho para armazenar o certificado autoassinado gerado para autenticação. Se não fornecido, o certificado será exibido como um blob Base64.
* `/password:<PASWORD>`: Opcional. Define a senha para o certificado autoassinado armazenado. Se não fornecido, uma senha aleatória será gerada.

Exemplo: **`Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1`**

{% hint style="info" %}
Mais opções no [**Readme**](https://github.com/eladshamir/Whisker).
{% endhint %}

## [pywhisker](https://github.com/ShutdownRepo/pywhisker) <a href="#7e2e" id="7e2e"></a>

pyWhisker é um equivalente em Python do Whisker original feito por Elad Shamir e escrito em C#. Essa ferramenta permite aos usuários manipular o atributo msDS-KeyCredentialLink de um usuário/computador alvo para obter controle total sobre esse objeto.

É baseado no Impacket e em um equivalente em Python do DSInternals de Michael Grafnetter chamado PyDSInternals feito por podalirius.
Essa ferramenta, juntamente com as PKINITtools de Dirk-jan, permitem uma exploração primitiva completa apenas em sistemas baseados em UNIX.


pyWhisker pode ser usado para operar várias ações no atributo msDs-KeyCredentialLink de um alvo

- *list*: lista todos os IDs e horários de criação atuais das KeyCredentials
- *info*: imprime todas as informações contidas em uma estrutura KeyCredential
- *add*: adiciona uma nova KeyCredential ao msDs-KeyCredentialLink
- *remove*: remove uma KeyCredential do msDs-KeyCredentialLink
- *clear*: remove todas as KeyCredentials do msDs-KeyCredentialLink
- *export*: exporta todas as KeyCredentials do msDs-KeyCredentialLink em JSON
- *import*: sobrescreve o msDs-KeyCredentialLink com KeyCredentials de um arquivo JSON


pyWhisker suporta as seguintes autenticações:
- (NTLM) Senha em texto puro
- (NTLM) Pass-the-hash
- (Kerberos) Senha em texto puro
- (Kerberos) Pass-the-key / Overpass-the-hash
- (Kerberos) Pass-the-cache (tipo de Pass-the-ticket)

![](https://github.com/ShutdownRepo/pywhisker/blob/main/.assets/add_pfx.png)


{% hint style="info" %}
Mais opções no [**Readme**](https://github.com/ShutdownRepo/pywhisker).
{% endhint %}

## [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

Em vários casos, o grupo "Everyone" / "Authenticated Users" / "Domain Users" ou algum outro **grupo amplo** contém quase todos os usuários no domínio e possui algumas DACLs de **GenericWrite** / **GenericAll** **sobre outros objetos** no domínio. [**ShadowSpray**](https://github.com/Dec0ne/ShadowSpray/) tenta **abusar** portanto das **Credenciais Shadow** sobre todos eles

Funciona da seguinte maneira:

1. **Faça login** no domínio com as credenciais fornecidas (ou use a sessão atual).
2. Verifique se o **nível funcional do domínio é 2016** (Caso contrário, pare, pois o ataque de Credenciais Shadow não funcionará)
3. Reúna uma **lista de todos os objetos** no domínio (usuários e computadores) do LDAP.
4. **Para cada objeto** na lista, faça o seguinte:
1. Tente **adicionar KeyCredential** ao atributo `msDS-KeyCredentialLink` do objeto.
2. Se o acima for **bem-sucedido**, use **PKINIT** para solicitar um **TGT** usando o KeyCredential adicionado.
3. Se o acima for **bem-sucedido**, execute um ataque **UnPACTheHash** para revelar o hash NT do usuário/computador.
4. Se **`--RestoreShadowCred`** foi especificado: Remova o KeyCredential adicionado (limpeza após o uso...)
5. Se **`--Recursive`** foi especificado: Faça o **mesmo processo** usando cada uma das contas de usuário/computador **que possuímos com sucesso**.

## Referências

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/) 

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) **grupo Discord** ou ao **grupo telegram** ou **siga-me** no **Twitter** **🐦** [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
