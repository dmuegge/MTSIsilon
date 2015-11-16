
# Load Modules
Import-Module MTSIsilon
Import-Module MTSMSExcel
Import-Module MTSGeneral

# Ignore certificate errors
Disable-CertificateValidation

# Set required connection information
$PWDFile = 'C:\Users\dmuegge\Dropbox\DTools\Scripts\PS\!Passwords\MLABDEV10-dmuegge-ISI-Admin.txt'
$DeptFolderFile = 'C:\Users\dmuegge\Dropbox\DTools\Scripts\PS\GitHub_Projects\MTSIsilon\Examples\Department_FolderPath.txt'

Set-ISIAPIConnectionInfo -username "admin" -passwordfile $PWDFile -baseurl "https://192.168.1.230:8080"


$AllQuotaResults = @()

$DeptFolders = Import-CSV -Path $DeptFolderFile | Sort-Object Department
$DeptFolders | Group Department | ForEach-Object {
    
    $QuotaResults = New-Object -TypeName psobject
    $QuotaResults | Add-Member -MemberType NoteProperty -Name 'Department' -Value $_.Name 
    
    $DeptLogical = $null
    $DeptPhysical = $null
    foreach($fp in $_.Group.'FolderPath'){

        $ISIQuotas = Get-ISIQuota | Where-Object { ($_.type -eq 'directory') -and ($_.path -eq $fp) } | Select path,usage
        $DeptLogical += $ISIQuotas.usage.logical
        $DeptPhysical += $ISIQuotas.usage.physical

    }

    $QuotaResults | Add-Member -MemberType NoteProperty -Name 'Logical-GB' -Value ([System.Math]::Round(($DeptLogical /1024 /1024 /1024),4))
    $QuotaResults | Add-Member -MemberType NoteProperty -Name 'Physical-GB' -Value ([System.Math]::Round(($DeptPhysical /1024 /1024 /1024),4))

    $AllQuotaResults += $QuotaResults
    
}

$ExcelApp = New-ExcelApplication -Visible
$ExcelWorkbook = New-ExcelWorkbook -ExcelApplication $ExcelApp


$ExcelSheet = Write-PSObjectToSheet -ExcelWorkbook $ExcelWorkbook -WorksheetName 'Department Legend' -InputObject $DeptFolders
Write-SheetFormatting -Worksheet $ExcelSheet -ExcelWorkbook $ExcelWorkbook -AutoFitCol -AutoFilter -FreezeTopPane

$ExcelSheet = Write-PSObjectToSheet -ExcelWorkbook $ExcelWorkbook -WorksheetName 'Department Usage' -InputObject $AllQuotaResults
Write-SheetFormatting -Worksheet $ExcelSheet -ExcelWorkbook $ExcelWorkbook -AutoFitCol -AutoFilter -FreezeTopPane

$QuotaInfo = Get-ISIQuota | where type -eq directory | Select path,@{Name="logical-gb";Expression={[System.Math]::Round((($_.usage.logical) /1024 /1024 /1024),4)}},@{Name="physical-gb";Expression={[System.Math]::Round((($_.usage.physical) /1024 /1024 /1024),4)}}

$ExcelSheet = Write-PSObjectToSheet -ExcelWorkbook $ExcelWorkbook -WorksheetName 'All Quotas' -InputObject $QuotaInfo
Write-SheetFormatting -Worksheet $ExcelSheet -ExcelWorkbook $ExcelWorkbook -AutoFitCol -AutoFilter -FreezeTopPane


$AllQuotaResults | FT -AutoSize
$QuotaInfo | FT -AutoSize



