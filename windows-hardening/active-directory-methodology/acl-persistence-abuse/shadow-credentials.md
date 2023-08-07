# Credenciais Shadow

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Introdução <a href="#3f17" id="3f17"></a>

Verifique a postagem original para [**todas as informações sobre essa técnica**](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).

Em **resumo**: se você pode escrever na propriedade **msDS-KeyCredentialLink** de um usuário/computador, você pode recuperar o **hash NT desse objeto**.

Isso ocorre porque você poderá definir credenciais de autenticação de chave pública-privada para o objeto e usá-las para obter um **Ticket de Serviço especial que contém seu hash NTLM** dentro do Certificado de Atributo de Privilégio (PAC) em uma entidade NTLM\_SUPPLEMENTAL\_CREDENTIAL criptografada que você pode descriptografar.

### Requisitos <a href="#2de4" id="2de4"></a>

Essa técnica requer o seguinte:

* Pelo menos um Controlador de Domínio do Windows Server 2016.
* Um certificado digital para Autenticação de Servidor instalado no Controlador de Domínio.
* Nível Funcional do Windows Server 2016 no Active Directory.
* Comprometer uma conta com os direitos delegados para escrever no atributo msDS-KeyCredentialLink do objeto de destino.

## Abuso

Abusar do Key Trust para objetos de computador requer etapas adicionais após obter um TGT e o hash NTLM da conta. Geralmente, existem duas opções:

1. Forjar um **ticket de prata RC4** para se passar por usuários privilegiados no host correspondente.
2. Usar o TGT para chamar **S4U2Self** para se passar por **usuários privilegiados** no host correspondente. Essa opção requer modificar o Ticket de Serviço obtido para incluir uma classe de serviço no nome do serviço.

O abuso do Key Trust tem a vantagem adicional de não delegar acesso a outra conta que possa ser comprometida - ele é **restrito à chave privada gerada pelo atacante**. Além disso, não requer a criação de uma conta de computador que pode ser difícil de limpar até que a escalada de privilégios seja alcançada.

Whisker

Junto com esta postagem, estou lançando uma ferramenta chamada " [Whisker](https://github.com/eladshamir/Whisker) ". Com base no código do DSInternals de Michael, o Whisker fornece uma camada C# para realizar esse ataque em compromissos. O Whisker atualiza o objeto de destino usando o LDAP, enquanto o DSInternals permite atualizar objetos usando tanto o LDAP quanto o RPC com o Serviço de Replicação de Diretório (DRS) Protocolo Remoto.

[Whisker](https://github.com/eladshamir/Whisker) tem quatro funções:

* Add — Esta função gera um par de chaves pública-privada e adiciona uma nova credencial de chave ao objeto de destino como se o usuário tivesse se inscrito no WHfB a partir de um novo dispositivo.
* List — Esta função lista todas as entradas do atributo msDS-KeyCredentialLink do objeto de destino.
* Remove — Esta função remove uma credencial de chave do objeto de destino especificado por um GUID de DeviceID.
* Clear — Esta função remove todos os valores do atributo msDS-KeyCredentialLink do objeto de destino. Se o objeto de destino estiver usando legítimamente o WHfB, isso irá quebrar.

## [Whisker](https://github.com/eladshamir/Whisker) <a href="#7e2e" id="7e2e"></a>

Whisker é uma ferramenta em C# para assumir contas de usuário e computador do Active Directory manipulando seu atributo `msDS-KeyCredentialLink`, adicionando efetivamente "Credenciais Shadow" à conta de destino.

[**Whisker**](https://github.com/eladshamir/Whisker) tem quatro funções:

* **Add** — Esta função gera um par de chaves pública-privada e adiciona uma nova credencial de chave ao objeto de destino como se o usuário tivesse se inscrito no WHfB a partir de um novo dispositivo.
* **List** — Esta função lista todas as entradas do atributo msDS-KeyCredentialLink do objeto de destino.
* **Remove** — Esta função remove uma credencial de chave do objeto de destino especificado por um GUID de DeviceID.
* **Clear** — Esta função remove todos os valores do atributo msDS-KeyCredentialLink do objeto de destino. Se o objeto de destino estiver usando legítimamente o WHfB, isso irá quebrar.

### Add

Adicione um novo valor ao atributo **`msDS-KeyCredentialLink`** de um objeto de destino:

* `/target:<samAccountName>`: Obrigatório. Defina o nome do alvo. Objetos de computador devem terminar com o sinal '$'.
* `/domain:<FQDN>`: Opcional. Defina o nome de domínio totalmente qualificado (FQDN) do alvo. Se não for fornecido, tentará resolver o FQDN do usuário atual.
* `/dc:<IP/HOSTNAME>`: Opcional. Defina o Controlador de Domínio (DC) de destino. Se não for fornecido, tentará direcionar o Controlador de Domínio Primário (PDC).
* `/path:<PATH>`: Opcional. Defina o caminho para armazenar o certificado autoassinado gerado para autenticação. Se não for fornecido, o certificado será exibido como um blob Base64.
* `/password:<PASWORD>`: Opcional. Defina a senha para o certificado autoassinado armazenado. Se não for fornecido, uma senha aleatória será gerada.

Exemplo: **`Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1`**

{% hint style="info" %}
Mais opções no [**Readme**](https://github.com/eladshamir/Whisker).
{% endhint %}
## [pywhisker](https://github.com/ShutdownRepo/pywhisker) <a href="#7e2e" id="7e2e"></a>

pyWhisker é um equivalente em Python do Whisker original feito por Elad Shamir e escrito em C#. Essa ferramenta permite aos usuários manipular o atributo msDS-KeyCredentialLink de um usuário/computador alvo para obter controle total sobre esse objeto.

É baseado no Impacket e em um equivalente em Python do DSInternals de Michael Grafnetter chamado PyDSInternals feito por podalirius.
Essa ferramenta, juntamente com as PKINITtools de Dirk-jan, permite uma exploração primitiva completa apenas em sistemas baseados em UNIX.


pyWhisker pode ser usado para realizar várias ações no atributo msDs-KeyCredentialLink de um alvo

- *list*: lista todos os IDs e horários de criação atuais do KeyCredentials
- *info*: imprime todas as informações contidas em uma estrutura KeyCredential
- *add*: adiciona um novo KeyCredential ao msDs-KeyCredentialLink
- *remove*: remove um KeyCredential do msDs-KeyCredentialLink
- *clear*: remove todos os KeyCredentials do msDs-KeyCredentialLink
- *export*: exporta todos os KeyCredentials do msDs-KeyCredentialLink em JSON
- *import*: sobrescreve o msDs-KeyCredentialLink com KeyCredentials de um arquivo JSON


pyWhisker suporta as seguintes autenticações:
- (NTLM) Senha em texto claro
- (NTLM) Pass-the-hash
- (Kerberos) Senha em texto claro
- (Kerberos) Pass-the-key / Overpass-the-hash
- (Kerberos) Pass-the-cache (tipo de Pass-the-ticket)

![](https://github.com/ShutdownRepo/pywhisker/blob/main/.assets/add_pfx.png)


{% hint style="info" %}
Mais opções no [**Readme**](https://github.com/ShutdownRepo/pywhisker).
{% endhint %}

## [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

Em vários casos, o grupo "Everyone" / "Authenticated Users" / "Domain Users" ou algum outro **grupo amplo** contém quase todos os usuários no domínio e possui algumas DACLs de `GenericWrite`/`GenericAll` **sobre outros objetos** no domínio. [**ShadowSpray**](https://github.com/Dec0ne/ShadowSpray/) tenta **abusar** portanto **ShadowCredentials** sobre todos eles

Funciona da seguinte maneira:

1. **Fazer login** no domínio com as credenciais fornecidas (ou usar a sessão atual).
2. Verificar se o **nível funcional do domínio é 2016** (Caso contrário, pare, pois o ataque Shadow Credentials não funcionará)
3. Coletar uma **lista de todos os objetos** no domínio (usuários e computadores) do LDAP.
4. **Para cada objeto** na lista, faça o seguinte:
1. Tente **adicionar KeyCredential** ao atributo `msDS-KeyCredentialLink` do objeto.
2. Se o acima for **bem-sucedido**, use **PKINIT** para solicitar um **TGT** usando o KeyCredential adicionado.
3. Se o acima for **bem-sucedido**, execute um ataque **UnPACTheHash** para revelar o **hash NT** do usuário/computador.
4. Se **`--RestoreShadowCred`** foi especificado: Remova o KeyCredential adicionado (limpe após si mesmo...)
5. Se **`--Recursive`** foi especificado: Faça o **mesmo processo** usando cada uma das contas de usuário/computador que possuímos com sucesso.

## Referências

* [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
* [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
