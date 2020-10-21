param(
    [Parameter(Mandatory=$true)]
    [string]$Path,

    [Parameter(Mandatory=$true)]
    [string]$WebsiteName
)

$schemaXml = New-Object xml
$schemaXml.Load($Path)

$entityNodes = $schemaXml.SelectNodes("/entities/entity")
$entityNodes | ForEach-Object {
    $entityNode = $_
    $websiteLookupNode = $entityNode.SelectSingleNode("descendant::fields/field[@lookupType='adx_website']")
    if($websiteLookupNode) {
        $filterNode = $entityNode.SelectSingleNode("descendant::filter")
        if(-not $filterNode) {
            $filterNode = $schemaXml.CreateElement("filter")
            $entityNode.AppendChild($filterNode) | Out-Null
        }
        $fetchXmlQuery = `
            "<fetch>" +
                "<entity name=`"$($entityNode.name)`">" +
                    "<attribute name=`"$($entityNode.primaryidfield)`" />" +
                    "<link-entity name=`"adx_website`" from=`"adx_websiteid`" to=`"$($websiteLookupNode.name)`">" +
                        "<filter>" +
                            "<condition attribute=`"adx_name`" operator=`"eq`" value=`"$WebsiteName`" />" +
                        "</filter>" +
                    "</link-entity>" +
                "</entity>" +
            "</fetch>"
        $filterNode.InnerText = $fetchXmlQuery
    }
}

$schemaXml.Save($Path)