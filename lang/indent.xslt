<?xml version="1.0"?>

<!--

  Remove all whitespace and propely indent the TS files

-->

<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
 <xsl:output method="xml" indent="yes"/>
 <xsl:strip-space elements="*"/>
 <xsl:template match="/">
  <xsl:copy-of select="."/>
 </xsl:template>
</xsl:stylesheet>
