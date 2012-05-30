# Single Sign-On (SSO) by SAP Logon Tickets #

SAP supports single sign-on via SAML now, but older versions use an earlier system called SAP logon tickets.  Logon tickets are digitally signed cookies named MYSAPSSO2.  With this gem, your app can do the following with this cookie:

* Find out which username is logged in
* Verify that the cookie wasn't tampered with (using the SAP installation's public key, which you need to supply to the app)
* Check the current time against the timestamps in the cookie

For an example of how to use this gem, see my [sso\_sap\_demo](https://github.com/danielstutzman/sso_sap_demo) repository.
