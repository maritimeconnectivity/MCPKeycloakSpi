// import enum for error lookup
AuthenticationFlowError = Java.type("org.keycloak.authentication.AuthenticationFlowError");
SerializedBrokeredIdentityContext = Java.type("org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext");


function authenticate(context) {

    LOG.info("Script Auth started!");

    LOG.info("Script Auth running 1");

    if (context.getClientSession().getNote("EXISTING_USER_INFO") != null) {
        context.attempted();
        return;
    }
    LOG.info("Script Auth running 2");

    var clientSession = context.getClientSession();
    var serializedCtx = SerializedBrokeredIdentityContext.readFromClientSession(clientSession, "BROKERED_CONTEXT");
    if (serializedCtx == null) {
        LOG.info("serializedCtx is null");
        context.failure(AuthenticationFlowError.IDENTITY_PROVIDER_ERROR);
        return;
    }
    LOG.info("Script Auth running 3");
    brokerContext = serializedCtx.deserialize(context.getSession(), clientSession);
    LOG.info("brokerCtx email: " + brokerContext.getEmail() + ", brokerCtx username: " + brokerContext.getModelUsername());    

    //var /*String*/ username = getUsername(context, brokerContext);
    // Normalize the username - an MRN created by simply appending the email to a predefined
    // MRN prefix in a mapper. the unnormalized username probably looks like this:
    // urn:mrn:mcl:user:dma:tgc@dma.dk
    // It should end up like this:
    // urn:mrn:mcl:user:dma:tgc
    var mrn_split = brokerContext.getModelUsername().split(":");
    var mrn_prefix = mrn_split.slice(0, mrn_split.length - 1).join(":");
    var email = mrn_split[mrn_split.length - 1];
    var username = mrn_prefix + ":" + email.split("@")[0];
    if (username == null) {
        LOG.info(realm.isRegistrationEmailAsUsername() ? "Email" : "Username");
        context.getClientSession().setNote("ENFORCE_UPDATE_PROFILE", "true");
        context.resetFlow();
        return;
    }

    LOG.info(script.name + " --> trace auth for: " + username);

    LOG.info("Script Auth running 4");

    //LOG.info("user email: " + user.email + ", user username: " + user.username);
    LOG.info("brokerCtx attributes: " + serializedCtx.getAttributes());
    //LOG.info("clientSession json: " + clientSession.getNote("BROKERED_CONTEXT"));


    // If the cert2oidc client is used, the certificate IDP must be used as well
    var /*String*/ cert2oidcClientName = "cert2oidc";
    var /*String*/ certificateIdpName = "certificates";
    var /*String*/ idpName = brokerContext.getIdpConfig().getAlias();
    var /*String*/ clientName = brokerContext.getClientSession().getClient().getClientId();
    LOG.infof("Coming from client '%s', using IDP '%s'.", clientName, idpName);
    if (clientName.toLowerCase().equals(cert2oidcClientName) && !idpName.toLowerCase().equals(certificateIdpName)) {
        context.failure(AuthenticationFlowError.INVALID_CLIENT_SESSION);
        return;
    }
    var /*UserModel*/ existingUser = context.getSession().users().getUserByUsername(username, context.getRealm());
    deleteDuplicateUserEmail(existingUser, context, brokerContext);

    // TODO: Do some check to ensure that only the certificate IDP + one other IDP is linked to a user.

    if (existingUser == null) {
        LOG.info("No duplication detected. Creating account for user '"+ username + "' and linking with identity provider: "+ brokerContext.getIdpConfig().getAlias());

        var /*UserModel*/ brokeredUser = session.users().addUser(realm, username);
        brokeredUser.setEnabled(true);
        brokeredUser.setEmail(brokerContext.getEmail());
        brokeredUser.setFirstName(brokerContext.getFirstName());
        brokeredUser.setLastName(brokerContext.getLastName());

        // Copy attributes to the new user
        // Do funky stuff to make this hybrid java/javascript work
        var StringArray = Java.type("java.lang.String[]");
        var a = new StringArray(2);
        var keys = serializedCtx.getAttributes().keySet().toArray(a)
        for (var i = 0; i < keys.length; i++) {
            var key = keys[i];
            brokeredUser.setAttribute(key, serializedCtx.getAttribute(key));
        }
        context.setUser(brokeredUser);
        context.getClientSession().setNote("BROKER_REGISTERED_NEW_USER", "true");
        //context.success();
    } else {
        LOG.info("Duplication detected. There is already existing user with username " + existingUser.getUsername());

        existingUser.setEmail(brokerContext.getEmail());
        existingUser.setFirstName(brokerContext.getFirstName());
        existingUser.setLastName(brokerContext.getLastName());
        // Attribute updating is done in IdentityBrokerService
        context.setUser(existingUser);
        //context.success();
    }

    LOG.info("Auth success! :D");
    context.success();
}


function getUsername(/*AuthenticationFlowContext*/ context, /*BrokeredIdentityContext*/ brokerContext) {
    // /*RealmModel*/ realm = context.getRealm();
    return realm.isRegistrationEmailAsUsername() ? brokerContext.getEmail() : brokerContext.getModelUsername();
}

function deleteDuplicateUserEmail(/*UserModel*/ existingUser, /*AuthenticationFlowContext*/ context, /*BrokeredIdentityContext*/ brokerContext) {
    var /*String*/ email = brokerContext.getEmail();
    if (email != null && !email.isEmpty()) {
        var /*UserModel*/ userWithEmail = context.getSession().users().getUserByEmail(email, context.getRealm());
        if (userWithEmail != null) {
            // Check if existingUser and the userWithEmail is the same
            if (existingUser != null && userWithEmail.getId().equals(existingUser.getId())) {
                // All is good - continue to merge/link the users
                LOG.info("existingUser and the userWithEmail is the same - continue to merge/link the users.");
                return;
            } else {
                // Found an existing user with the same email - delete it!
                LOG.warn("Found an existing user with the same email - delete it!");
                context.getSession().users().removeUser(context.getRealm(), userWithEmail);
            }
        } else {
            LOG.info("Did not find any conflicting users.");
        }
    } else {
        LOG.info("The user has no email - so no conflict...");
    }
}
