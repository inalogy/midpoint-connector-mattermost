# connector-mattermost

Polygon/ConnId connector for Mattermost

## Description

Connector for [Mattermost](https://mattermost.com/) using [REST API](https://api.mattermost.com/#tag/introduction). 

## Capabilities and Features

* Schema: YES
* Provisioning: YES
* Live Synchronization: No
* Password: YES
* Activation: YES
* Script execution: No 

Mattermost Connector contains support for USER entity.  

## Build

[Download](https://github.com/inalogy/midpoint-connector-mattermost) and build the project with usual:

```
mvn clean install
```

After successful the build, you can find `connector-mattermost-1.0.0.2.jar` in `target` directory.

## Configuring resource

* create Bot account: https://docs.mattermost.com/developer/bot-accounts.html
* set authMethod=TOKEN, tokenName=Authorization, tokenValue=Bearer + token  (prefix "Bearer " required)
* alternatively use Personal account with authMethod=NONE and username, password attributes or Personal Access Tokens (https://docs.mattermost.com/developer/personal-access-tokens.html)
* inspire by [sample](https://github.com/inalogy/midpoint-connector-mattermost/blob/main/sample/resource.xml) to configure your own resource

## License

Licensed under the [Apache License 2.0](/LICENSE).

## Status

Mattermost Connector is intended for production use. Tested with MidPoint version 4.1, Mattermost version: 5.31.1. The connector was introduced as a contribution to midPoint project by [Inalogy](https://inalogy.com) and is not officially supported by Evolveum.
If you need support, please contact info@inalogy.com.