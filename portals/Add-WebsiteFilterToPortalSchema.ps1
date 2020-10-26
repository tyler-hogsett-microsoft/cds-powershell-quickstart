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
        [string]$ParentEntityWebsiteLookupName = "adx_websiteid",
        [string]$GrandparentEntityName,
        [string]$GrandparentEntityLookupName = "$($GrandParentEntityName)id",
        [string]$GrandparentEntityWebsiteLookupName = "adx_websiteid"
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
                "<link-entity name=`"$ParentEntityName`" from=`"$ParentEntityLookupName`" to=`"$($ParentEntityName)id`">" +
                    (% {
                        if([string]::IsNullOrEmpty($GrandParentEntityName)) {
                            "<link-entity name=`"adx_website`" from=`"adx_websiteid`" to=`"$ParentEntityWebsiteLookupName`">" +
                                "<filter>" +
                                    "<condition attribute=`"adx_name`" operator=`"eq`" value=`"$WebsiteName`" />" +
                                "</filter>" +
                            "</link-entity>"
                        } else {
                            "<link-entity name=`"$GrandparentEntityName`" from=`"$GrandparentEntityLookupName`" to=`"$($GrandparentEntityName)id`">" +
                                "<link-entity name=`"adx_website`" from=`"adx_websiteid`" to=`"$GrandparentEntityWebsiteLookupName`">" +
                                    "<filter>" +
                                        "<condition attribute=`"adx_name`" operator=`"eq`" value=`"$WebsiteName`" />" +
                                    "</filter>" +
                                "</link-entity>" +
                            "</link-entity>"
                        }
                    }) +
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
Add-FetchXmlToChildEntity `
    -EntityName "adx_entityformmetadata" `
    -ParentEntityName "adx_entityform" `
    -ParentEntityLookupName "adx_entityform"
Add-FetchXmlToChildEntity `
    -EntityName "adx_webformmetadata" `
    -ParentEntityName "adx_webformstep" `
    -ParentEntityLookupName "adx_webformstep" `
    -GrandparentEntityName "adx_webform" `
    -GrandparentEntityLookupName "adx_webform"
Add-FetchXmlToChildEntity `
    -EntityName "adx_webformstep" `
    -ParentEntityName "adx_webform" `
    -ParentEntityLookupName "adx_webform"
Add-FetchXmlToChildEntity `
    -EntityName "adx_polloption" `
    -ParentEntityName "adx_poll"
Add-FetchXmlToChildEntity `
    -EntityName "adx_communityforumannouncement" `
    -ParentEntityName "adx_communityforum" `
    -ParentEntityLookupName "adx_forumid"
Add-FetchXmlToChildEntity `
    -EntityName "adx_communityforumaccesspermission" `
    -ParentEntityName "adx_communityforum" `
    -ParentEntityLookupName "adx_forumid"

$schemaXml.Save($Path)