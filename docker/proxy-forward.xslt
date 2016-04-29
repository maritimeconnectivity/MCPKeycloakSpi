<?xml version="1.0" encoding="UTF-8"?>

<xsl:stylesheet version="2.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:ut="urn:jboss:domain:undertow:3.0"
                xmlns:do="urn:jboss:domain:4.0">

    <xsl:output method="xml" indent="yes"/>

    <xsl:template match="//ut:http-listener">
        <ut:http-listener name="default" socket-binding="http" redirect-socket="proxy-https" proxy-address-forwarding="true"/>
    </xsl:template>

    <xsl:template match="//do:socket-binding[@name='https']">
        <xsl:copy-of select="."/>
        <do:socket-binding name="proxy-https" port="443"/>
    </xsl:template>

    <xsl:template match="@*|node()">
        <xsl:copy>
            <xsl:apply-templates select="@*|node()"/>
        </xsl:copy>
    </xsl:template>

</xsl:stylesheet>
