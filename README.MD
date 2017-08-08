Identity provider authentication
--------------------------------

##Overview

   Identity provider authentication will take care of authenticating the user/account in  third party server, based on the response it will authorize user/account in Gooru system.

**Supported identity provider methods**
   
   - Google
   - WSFED
   - SAML

**Configuration**
   
   ```config.json``` file has  all the configuration details like callback urls, client ID or Key etc.

##How to setup ?
   
   - Install  nodejs
   - Clone the project
   - In home path of the project install all packages, using below command,
   - ```npm install && npm install -g forever```

##How to setup Shibboleth IdP ?

   - Generate the metadata using ```/api/nucleus-auth-idp/v1/shibboleth/generateMetadata``` from the environment 
     where this service is running e.g.```http://www.gooru.org/api/nucleus-auth-idp/v1/shibboleth/generateMetadata```
   - Share the metadata with partners to upload on Shibboleth IdP
   - There is no need to creating a new route for a new partner. Partners are required to pass the shibboleth IdP 
     entryPoint in the request and that will redirect user to their IdP for authentication
     e.g. ```http://www.gooru.org/api/nucleus-auth-idp/v1/shibboleth?entryPoint=https://idp.testshib.org/idp/profile/SAML2/Redirect/SSO```




