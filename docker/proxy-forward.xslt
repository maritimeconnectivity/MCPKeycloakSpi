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

    <xsl:template match="//ks:spi[@name='jta-lookup']">
        <xsl:copy-of select="."/>
        <!-- Custom SPIs below -->
        <ks:spi name="eventsListener">
            <ks:provider name="mc-event-listener" enabled="true">
                <ks:properties>
                    <ks:property name="server-root">
                        <xsl:attribute name="value">${env.MC_IDREG_SERVER_ROOT:https://localhost}</xsl:attribute>
                    </ks:property>
                    <ks:property name="keystore-path">
                        <xsl:attribute name="value">${env.SYNC_KEYSTORE_PATH:/mc-eventprovider-conf/idbroker-updater.jks}</xsl:attribute>
                    </ks:property>
                    <ks:property name="keystore-password">
                        <xsl:attribute name="value">${env.SYNC_KEYSTORE_PASSWORD:changeit}</xsl:attribute>
                    </ks:property>
                    <ks:property name="truststore-path">
                        <xsl:attribute name="value">${env.SYNC_TRUSTSTORE_PATH}</xsl:attribute>
                    </ks:property>
                    <ks:property name="truststore-password">
                        <xsl:attribute name="value">${env.SYNC_TRUSTSTORE_PASSWORD}</xsl:attribute>
                    </ks:property>
                    <ks:property name="idp-not-to-sync">
                        <xsl:attribute name="value">${env.NOSYNC_IDPS:certificates,projecttestusers}</xsl:attribute>
                    </ks:property>
                </ks:properties>
            </ks:provider>
        </ks:spi>
        <ks:spi name="authenticator">
            <ks:provider name="certificate" enabled="true">
                <ks:properties>
                    <ks:property name="truststore-path">
                        <xsl:attribute name="value">${env.CERT_TRUSTSTORE_PATH:/mc-eventprovider-conf/mc-truststore.jks}</xsl:attribute>
                    </ks:property>
                    <ks:property name="truststore-password">
                        <xsl:attribute name="value">${env.CERT_TRUSTSTORE_PATH:changeit}</xsl:attribute>
                    </ks:property>
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
