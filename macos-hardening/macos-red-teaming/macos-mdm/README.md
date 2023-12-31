# macOS MDM

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Básicos

### O que é MDM (Gerenciamento de Dispositivos Móveis)?

[Gerenciamento de Dispositivos Móveis](https://en.wikipedia.org/wiki/Mobile\_device\_management) (MDM) é uma tecnologia comumente usada para **administrar dispositivos de computação de usuários finais**, como telefones móveis, laptops, desktops e tablets. No caso de plataformas da Apple como iOS, macOS e tvOS, refere-se a um conjunto específico de recursos, APIs e técnicas usadas por administradores para gerenciar esses dispositivos. O gerenciamento de dispositivos via MDM requer um servidor MDM comercial ou de código aberto compatível que implemente suporte para o [Protocolo MDM](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf).

* Uma maneira de alcançar o **gerenciamento centralizado de dispositivos**
* Requer um **servidor MDM** que implemente suporte para o protocolo MDM
* O servidor MDM pode **enviar comandos MDM**, como limpeza remota ou “instalar esta configuração”

### Básicos O que é DEP (Programa de Inscrição de Dispositivos)?

O [Programa de Inscrição de Dispositivos](https://www.apple.com/business/site/docs/DEP\_Guide.pdf) (DEP) é um serviço oferecido pela Apple que **simplifica** a inscrição no Gerenciamento de Dispositivos Móveis (MDM) oferecendo **configuração zero-touch** de dispositivos iOS, macOS e tvOS. Ao contrário dos métodos de implantação mais tradicionais, que exigem que o usuário final ou administrador tome medidas para configurar um dispositivo ou se inscreva manualmente em um servidor MDM, o DEP visa iniciar esse processo, **permitindo que o usuário desembale um novo dispositivo Apple e o tenha configurado para uso na organização quase imediatamente**.

Os administradores podem aproveitar o DEP para inscrever automaticamente dispositivos no servidor MDM de sua organização. Uma vez que um dispositivo está inscrito, **em muitos casos é tratado como um dispositivo "confiável"** de propriedade da organização e pode receber qualquer número de certificados, aplicativos, senhas de WiFi, configurações de VPN [e assim por diante](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf).

* Permite que um dispositivo se inscreva automaticamente em um servidor MDM pré-configurado na **primeira vez que é ligado**
* Mais útil quando o **dispositivo** é **novo em folha**
* Também pode ser útil para fluxos de trabalho de **reprovisionamento** (**limpo** com instalação nova do SO)

{% hint style="danger" %}
Infelizmente, se uma organização não tomou medidas adicionais para **proteger sua inscrição no MDM**, um processo de inscrição simplificado para o usuário final através do DEP também pode significar um processo simplificado para **atacantes inscreverem um dispositivo de sua escolha no servidor MDM da organização**, assumindo a "identidade" de um dispositivo corporativo.
{% endhint %}

### Básicos O que é SCEP (Protocolo Simples de Inscrição de Certificados)?

* Um protocolo relativamente antigo, criado antes que o TLS e o HTTPS fossem amplamente utilizados.
* Fornece aos clientes uma maneira padronizada de enviar uma **Solicitação de Assinatura de Certificado** (CSR) com o objetivo de obter um certificado. O cliente pedirá ao servidor que lhe conceda um certificado assinado.

### O que são Perfis de Configuração (também conhecidos como mobileconfigs)?

* A maneira oficial da Apple de **definir/aplicar a configuração do sistema.**
* Formato de arquivo que pode conter vários payloads.
* Baseado em listas de propriedades (do tipo XML).
* “podem ser assinados e criptografados para validar sua origem, garantir sua integridade e proteger seu conteúdo.” Básicos — Página 70, Guia de Segurança do iOS, Janeiro de 2018.

## Protocolos

### MDM

* Combinação de APNs (**servidores Apple**) + API RESTful (**servidores de fornecedores MDM**)
* **Comunicação** ocorre entre um **dispositivo** e um servidor associado a um **produto de gerenciamento de dispositivos**
* **Comandos** entregues do MDM para o dispositivo em **dicionários codificados em plist**
* Tudo sobre **HTTPS**. Servidores MDM podem ser (e geralmente são) fixados.
* A Apple concede ao fornecedor MDM um **certificado APNs** para autenticação

### DEP

* **3 APIs**: 1 para revendedores, 1 para fornecedores MDM, 1 para identidade do dispositivo (não documentada):
* A chamada [API "serviço em nuvem" DEP](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf). Esta é usada pelos servidores MDM para associar perfis DEP a dispositivos específicos.
* A [API DEP usada por Revendedores Autorizados Apple](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html) para inscrever dispositivos, verificar o status da inscrição e verificar o status da transação.
* A API privada DEP não documentada. Esta é usada por Dispositivos Apple para solicitar seu perfil DEP. No macOS, o binário `cloudconfigurationd` é responsável por se comunicar através desta API.
* Mais moderna e baseada em **JSON** (em vez de plist)
* A Apple concede um **token OAuth** ao fornecedor MDM

**API "serviço em nuvem" DEP**

* RESTful
* sincroniza registros de dispositivos da Apple para o servidor MDM
* sincroniza “perfis DEP” para a Apple do servidor MDM (entregue pela Apple ao dispositivo mais tarde)
* Um perfil DEP contém:
* URL do servidor do fornecedor MDM
* Certificados confiáveis adicionais para URL do servidor (fixação opcional)
* Configurações extras (por exemplo, quais telas pular no Assistente de Configuração)

## Número de Série

Dispositivos Apple fabricados após 2010 geralmente têm números de série **alphanumericos de 12 caracteres**, com os **primeiros três dígitos representando o local de fabricação**, os dois seguintes indicando o **ano** e a **semana** de fabricação, os próximos **três** dígitos fornecendo um **identificador único**, e os **últimos quatro dígitos representando o número do modelo**.

{% content-ref url="macos-serial-number.md" %}
[macos-serial-number.md](macos-serial-number.md)
{% endcontent-ref %}

## Etapas para inscrição e gerenciamento

1. Criação do registro do dispositivo (Revendedor, Apple): O registro do novo dispositivo é criado
2. Atribuição do registro do dispositivo (Cliente): O dispositivo é atribuído a um servidor MDM
3. Sincronização do registro do dispositivo (fornecedor MDM): MDM sincroniza os registros dos dispositivos e empurra os perfis DEP para a Apple
4. Check-in DEP (Dispositivo): Dispositivo obtém seu perfil DEP
5. Recuperação do perfil (Dispositivo)
6. Instalação do perfil (Dispositivo) a. incl. MDM, SCEP e cargas úteis da CA raiz
7. Emissão de comando MDM (Dispositivo)

![](<../../../.gitbook/assets/image (564).png>)

O arquivo `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` exporta funções que podem ser consideradas **etapas "de alto nível"** do processo de inscrição.

### Etapa 4: Check-in DEP - Obtendo o Registro de Ativação

Esta parte do processo ocorre quando um **usuário inicia um Mac pela primeira vez** (ou após uma limpeza completa)

![](<../../../.gitbook/assets/image (568).png>)

ou ao executar `sudo profiles show -type enrollment`

* Determinar **se o dispositivo está habilitado para DEP**
* Registro de Ativação é o nome interno para **perfil DEP**
* Começa assim que o dispositivo é conectado à Internet
* Impulsionado por **`CPFetchActivationRecord`**
* Implementado por **`cloudconfigurationd`** via XPC. O **"Assistente de Configuração"** (quando o dispositivo é inicializado pela primeira vez) ou o comando **`profiles`** irão **contatar este daemon** para recuperar o registro de ativação.
* LaunchDaemon (sempre executa como root)

Segue alguns passos para obter o Registro de Ativação realizados por **`MCTeslaConfigurationFetcher`**. Este processo usa uma criptografia chamada **Absinthe**

1. Recuperar **certificado**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. **Inicializar** estado a partir do certificado (**`NACInit`**)
1. Usa vários dados específicos do dispositivo (ou seja, **Número de Série via `IOKit`**)
3. Recuperar **chave de sessão**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. Estabelecer a sessão (**`NACKeyEstablishment`**)
5. Fazer a solicitação
1. POST para [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) enviando os dados `{ "action": "RequestProfileConfiguration", "sn": "" }`
2. O payload JSON é criptografado usando Absinthe (**`NACSign`**)
3. Todas as solicitações sobre HTTPs, certificados raiz embutidos são usados

![](<../../../.gitbook/assets/image (566).png>)

A resposta é um dicionário JSON com alguns dados importantes como:

* **url**: URL do host do fornecedor MDM para o perfil de ativação
* **anchor-certs**: Array de certificados DER usados como âncoras confiáveis

### **Etapa 5: Recuperação do Perfil**

![](<../../../.gitbook/assets/image (567).png>)

* Solicitação enviada para **url fornecida no perfil DEP**.
* **Certificados âncora** são usados para **avaliar a confiança** se fornecidos.
* Lembrete: a propriedade **anchor\_certs** do perfil DEP
* **Solicitação é um simples .plist** com identificação do dispositivo
* Exemplos: **UDID, versão do SO**.
* Assinado CMS, codificado DER
* Assinado usando o **certificado de identidade do dispositivo (de APNS)**
* **Cadeia de certificados** inclui expirado **Apple iPhone Device CA**

![](<../../../.gitbook/assets/image (567) (1) (2) (2) (2) (2) (2) (2) (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1. (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1
