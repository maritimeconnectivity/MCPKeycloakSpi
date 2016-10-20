<?xml version="1.0" encoding="UTF-8"?>

<xsl:stylesheet version="2.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:ut="urn:jboss:domain:undertow:3.0"
                xmlns:do="urn:jboss:domain:4.0"
                xmlns:ks="urn:jboss:domain:keycloak-server:1.1">

    <xsl:output method="xml" indent="yes"/>

    <xsl:template match="//ut:http-listener">
        <ut:http-listener name="default" socket-binding="http" redirect-socket="proxy-https" proxy-address-forwarding="true"/>
    </xsl:template>

    <xsl:template match="//do:socket-binding[@name='https']">
        <xsl:copy-of select="."/>
        <do:socket-binding name="proxy-https" port="443"/>
    </xsl:template>

    <xsl:template match="//ks:subsystem">
        <xsl:copy-of select="."/>
        <!-- Custom SPIs below -->
        <ks:spi name="eventsListener">
            <ks:provider name="mc-event-listener" enabled="true">
                <ks:properties>
                    <ks:property name="server-root" value="${env.MC_IDREG_SERVER_ROOT:https://localhost}"/>
                    <ks:property name="keystore-path" value="${env.KEYSTORE_PATH:/mc-eventprovider-conf/idbroker-updater.jks}"/>
                    <ks:property name="keystore-password" value="${env.KEYSTORE_PASSWORD:changeit}"/>
                    <ks:property name="truststore-path" value="${env.TRUSTSTORE_PATH:/mc-eventprovider-conf/mc-truststore.jks}"/>
                    <ks:property name="truststore-password" value="${env.TRUSTSTORE_PASSWORD:changeit}"/>
                    <ks:property name="idp-not-to-sync" value="${env.NOSYNC_IDPS:certificates,projecttestusers}"/>
                </ks:properties>
            </ks:provider>
        </ks:spi>
        <ks:spi name="authenticator">
            <ks:provider name="certificate" enabled="true">
                <ks:properties>
                    <ks:property name="truststore-path" value="${env.TRUSTSTORE_PATH:/mc-eventprovider-conf/mc-truststore.jks}"/>
                    <ks:property name="truststore-password" value="${env.TRUSTSTORE_PATH:changeit}"/>
                </ks:properties>
            </ks:provider>
            <ks:provider name="idp-update-no-promt" enabled="true"/>
        </ks:spi>
    </xsl:template>


    <xsl:template match="@*|node()">
        <xsl:copy>
            <xsl:apply-templates select="@*|node()"/>
        </xsl:copy>
    </xsl:template>

</xsl:stylesheet>
