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

function Add-FetchXmlToChildEntity
{
    param(
        [Parameter(Mandatory=$true)]
        [string]$EntityName,
        [Parameter(Mandatory=$true)]
        [string]$ParentEntityName,
        [string]$ParentEntityLookupName = "$($ParentEntityName)id",
        [string]$ParentEntityWebsiteLookupName = "adx_websiteid"
    )

    $entityNode = $schemaXml.SelectSingleNode("/entities/entity[@name='$EntityName']")
    $filterNode = $entityNode.SelectSingleNode("descendant::filter")
    if(-not $filterNode) {
        $filterNode = $schemaXml.CreateElement("filter")
        $entityNode.AppendChild($filterNode) | Out-Null
    }
    $fetchXmlQuery = `
        "<fetch>" +
            "<entity name=`"$EntityName`">" +
                "<attribute name=`"$($EntityName)id`" />" +
                "<link-entity name=`"adx_webfile`" from=`"adx_webfileid`" to=`"$ParentEntityLookupName`">" +
                    "<link-entity name=`"adx_website`" from=`"adx_websiteid`" to=`"$ParentEntityWebsiteLookupName`">" +
                        "<filter>" +
                            "<condition attribute=`"adx_name`" operator=`"eq`" value=`"$WebsiteName`" />" +
                        "</filter>" +
                    "</link-entity>" +
                "</link-entity>" +
            "</entity>" +
        "</fetch>"
    $filterNode.InnerText = $fetchXmlQuery
}

Add-FetchXmlToChildEntity `
    -EntityName "annotation" `
    -ParentEntityName "adx_webfile" `
    -ParentEntityLookupName "objectid"
Add-FetchXmlToChildEntity `
    -EntityName "adx_weblink" `
    -ParentEntityName "adx_weblinkset"




$schemaXml.Save($Path)