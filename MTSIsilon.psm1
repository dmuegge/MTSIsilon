<# Module Name:     MTSIsilon
## Author:          David Muegge
## Purpose:         Provides cmdlets for : Performing operations on an Isilon cluster via Isilon ReST API and SSH
##																					
## Requirements:    PowerShell Version 3
## 					
##					
## History:
##                  0.0.98 2013-2-25 - Initial Version
##                  
##
##                                  
##                                                                             
####################################################################################################
## Disclaimer
##  ****************************************************************
##  * DO NOT USE IN A PRODUCTION ENVIRONMENT UNTIL YOU HAVE TESTED *
##  * THOROUGHLY IN A LAB ENVIRONMENT. USE AT YOUR OWN RISK.  IF   *
##  * YOU DO NOT UNDERSTAND WHAT THIS SCRIPT DOES OR HOW IT WORKS, *
##  * DO NOT USE IT OUTSIDE OF A SECURE, TEST SETTING.             *
##  ****************************************************************
###################################################################################################>


function New-PasswordFile{
<#
.SYNOPSIS
    Creates enrypted password file

.DESCRIPTION
    Will prompt for password and write encrypted password to file
    Encryption key is generated based on current windows user security token

.PARAMETER Path
    Path to location of encrypted password file

.PARAMETER Filename
    Filename of enrypted password file

.INPUTS
    Filename and path
    Will prompt for password to be encrypted

.OUTPUTS
    Encrypted password file

.EXAMPLE
    New-PasswordFile -Path "C:\Temp\Passwords" -Filename "lab-dmuegge-IS7TEST01-PWD.txt"

.NOTES
    This cmdlet is used allow the use of basic authentication and persist authentication info without the use of cookies

#>

	[CmdletBinding()]
	
	param ( 
		[Parameter(Mandatory=$True)][string]$Path, `
		[Parameter(Mandatory=$True)][string]$Filename
	)

    Begin{
	
        Try{
            
            If(Test-Path $Path){
	            $passwd = Read-Host -prompt "Password" -assecurestring
                $FullFilePath = $Path + "\" + $Filename
                New-Item -Path $FullFilePath -ItemType File
	            ConvertFrom-SecureString -securestring $passwd | Out-File -FilePath $FullFilePath.ToString()
            }
            Else
            {
                Write-Error "[New-PasswordFile] :: Path file not found: " $Path
            }

        }
        Catch{
            
            Write-Error $_

        }

	}
    Process{

    }
    End{

    }
}

function Get-PasswordFromFile{
<#
.SYNOPSIS
   Get password from encrypted password file 

.DESCRIPTION
    Will prompt for password and write encrypted password to file
    Encryption key is generated based on current windows user security token

.PARAMETER Path
    Path to location of encrypted password file
        Required?                    true 
        Position?                    named
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false

.PARAMETER Filename
    Filename of enrypted password file
        Required?                    true 
        Position?                    named
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false

.INPUTS
    Filename and path
    
.OUTPUTS
    Encrypted password file

.EXAMPLE
    New-PasswordFile -Path "C:\Temp\Passwords" -Filename "lab-dmuegge-IS7TEST01-PWD.txt"

.NOTES
    This cmdlet is used allow the use of basic authentication and persist authentication info without the use of cookies

#>

	[CmdletBinding()]
	
	param ( 
		[Parameter(Mandatory=$True)][string]$FullPath
	)

    Begin{

        Try{

            # Test file existence and retrieve file object
            If(Test-Path -Path $FullPath){

                $File = Get-item -Path $FullPath
                $filedata = Get-Content -Path $File.FullName
                $password = ConvertTo-SecureString $filedata
                $BSTR = [System.Runtime.InteropServices.marshal]::SecureStringToBSTR($password)
                $password = [System.Runtime.InteropServices.marshal]::PtrToStringAuto($BSTR)
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
                return $password

            }
            else
            {
                
                Write-Error "[Get-PasswordFromFile] :: Password file not found: " $FullPath

            }
                        

        }
        Catch{

            Write-Verbose "[Get-PasswordFromFile] :: threw an exception: $_"
            Write-Error $_

        }
    }
    Process{



    }
    End{

    }
			
}

function Set-ISISSHConnectionInfo{
<#
.SYNOPSIS
    Set Isilon Connection Information
    
.DESCRIPTION
    Stores Isilon platform API connection information

.PARAMETER username
    id of ADS provider to update
        Required?                    true 
        Position?                    named
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false

.PARAMETER passwordfile
    id of ADS provider to update
        Required?                    true 
        Position?                    named
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false

.PARAMETER sshserver
    id of ADS provider to update
        Required?                    true 
        Position?                    named
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false

 
.EXAMPLE
    Set-ISIAPIConnectionInfo -username "admin" -passwordfile "C:\temp\password.txt" -sshserver "testisi.lab.local"

.NOTES
    Password file is created using the New-PasswordFile cmdlet


#>

	[CmdletBinding()]
	
	param ([Parameter(Mandatory=$True)][string]$username,[Parameter(Mandatory=$True)][string]$passwordfile,[Parameter(Mandatory=$True)][string]$sshserver)

    

    # Set SSH server address and root user
    $rootuser = $username

    # Set SSH root user credential for isi commands
    $PlainPassword = Get-PasswordFromFile -FullPath $PasswordFile
    $SecurePassword = $PlainPassword | ConvertTo-SecureString -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential -ArgumentList $rootuser, $SecurePassword

    New-Variable -Name ISISSHServer -Value $sshserver -Scope Global -Force
    New-Variable -Name ISISSHCred -Value $cred -Scope Global -Force


    
			
}

Export-ModuleMember New-PasswordFile
Export-ModuleMember Get-PasswordFromFile
Export-ModuleMember Set-ISISSHConnectionInfo


# SSH isi functions
function Get-ISIStatus{
<#
.SYNOPSIS
    Get Isilon cluster status
    
.DESCRIPTION
    Returns Isilon cluster status

.EXAMPLE
    Get-ISIStatus


.NOTES

#>

	[CmdletBinding()]
	
	param ()

    Invoke-SSH -server $ISISSHServer -Credential $ISISSHCred -Command "isi status" -Force
			
}

function Get-ISIVersion{
<#
.SYNOPSIS
    Get Isilon cluster version
    
.DESCRIPTION
    Returns Isilon cluster version

.EXAMPLE
    Get-ISIVersion


.NOTES

#>

	[CmdletBinding()]
	
	param ()

    Invoke-SSH -server $ISISSHServer -Credential $ISISSHCred -Command "isi version" -Force
			
}

function Get-ISIFirmware{
<#
.SYNOPSIS
    Get Isilon cluster firmware
    
.DESCRIPTION
    Returns Isilon cluster firmware

.EXAMPLE
    Get-ISIFirmware


.NOTES

#>

	[CmdletBinding()]
	
	param ()

    Invoke-SSH -server $ISISSHServer -Credential $ISISSHCred -Command "isi firmware" -Force
			
}

function Get-ISIPerfstat{
<#
.SYNOPSIS
    Get Isilon cluster performance status
    
.DESCRIPTION
    Returns Isilon cluster performance status

.EXAMPLE
    Get-ISIPerfstat


.NOTES

#>

	[CmdletBinding()]
	
	param ()

    Invoke-SSH -server $ISISSHServer -Credential $ISISSHCred -Command "isi perfstat" -Force
			
}

function Get-ISIDevices{
<#
.SYNOPSIS
    Get Isilon node devices
    
.DESCRIPTION
    Returns Isilon node disk devices

.EXAMPLE
    Get-ISIDevices


.NOTES

#>

	[CmdletBinding()]
	
	param ()

    Invoke-SSH -server $ISISSHServer -Credential $ISISSHCred -Command "isi devices" -Force
			
}

function Get-ISIPstat{
<#
.SYNOPSIS
    Get Isilon pstat statistics
    
.DESCRIPTION
    Returns Isilon 

.EXAMPLE
    Get-ISIPstat


.NOTES

#>

	[CmdletBinding()]
	
	param ()

    Invoke-SSH -server $ISISSHServer -Credential $ISISSHCred -Command "isi statistics pstat" -Force
			
}

function Get-ISIEvent{
<#
.SYNOPSIS
    Get Isilon events
    
.DESCRIPTION
    Returns Isilon 

.EXAMPLE
    Get-ISIEvent


.NOTES

#>

	[CmdletBinding()]
	
	param ()

    Invoke-SSH -server $ISISSHServer -Credential $ISISSHCred -Command "isi events" -Force
			
}

function Get-ISINetwork{
<#
.SYNOPSIS
    Get Isilon networks
    
.DESCRIPTION
    Returns Isilon ntworks

.EXAMPLE
    Get-ISINetwork


.NOTES

#>

	[CmdletBinding()]
	
	param ()

    Invoke-SSH -server $ISISSHServer -Credential $ISISSHCred -Command "isi networks" -Force
			
}

function Get-ISIStatisticsDrive{
<#
.SYNOPSIS
    Get Isilon drive statistics
    
.DESCRIPTION
    Returns Isilon ddrive statistics

.EXAMPLE
    Get-ISIStatisticsDrive


.NOTES

#>

	[CmdletBinding()]
	
	param ()

    Invoke-SSH -server $ISISSHServer -Credential $ISISSHCred -Command "isi statistics drive" -Force
			
}

function Get-ISIStatisticsClient{
<#
.SYNOPSIS
    Get Isilon client statistics
    
.DESCRIPTION
    Returns Isilon client statistics

.EXAMPLE
    Get-ISIStatisticsClient


.NOTES

#>

	[CmdletBinding()]
	
	param ()

    Invoke-SSH -server $ISISSHServer -Credential $ISISSHCred -Command "isi statistics client" -Force
			
}

function Get-ISIStatisticsProtocol{
<#
.SYNOPSIS
    Get Isilon protocol statistics
    
.DESCRIPTION
    Returns Isilon protocol statistics

.EXAMPLE
    Get-ISIStatisticsProtocol


.NOTES

#>

	[CmdletBinding()]
	
	param ()

    Invoke-SSH -server $ISISSHServer -Credential $ISISSHCred -Command "isi statistics protocol" -Force
			
}

function Get-ISIStatisticsSystem{
<#
.SYNOPSIS
    Get Isilon System statistics
    
.DESCRIPTION
    Returns Isilon System statistics

.EXAMPLE
    Get-ISIStatisticsSystem


.NOTES

#>

	[CmdletBinding()]
	
	param ()

    Invoke-SSH -server $ISISSHServer -Credential $ISISSHCred -Command "isi statistics system" -Force
			
}

function Get-ISIStatisticsHeat{
<#
.SYNOPSIS
    Get Isilon heat statistics
    
.DESCRIPTION
    Returns Isilon heat statistics

.EXAMPLE
    Get-ISIStatisticsHeat


.NOTES

#>

	[CmdletBinding()]
	
	param ()

    Invoke-SSH -server $ISISSHServer -Credential $ISISSHCred -Command "isi statistics heat" -Force
			
}

Export-ModuleMember Get-ISIStatus
Export-ModuleMember Get-ISIVersion
Export-ModuleMember Get-ISIFirmware
Export-ModuleMember Get-ISIPerfstat
Export-ModuleMember Get-ISIDevices
Export-ModuleMember Get-ISIPstat
Export-ModuleMember Get-ISIEvent
Export-ModuleMember Get-ISINetwork
Export-ModuleMember Get-ISIStatisticsDrive
Export-ModuleMember Get-ISIStatisticsClient
Export-ModuleMember Get-ISIStatisticsProtocol
Export-ModuleMember Get-ISIStatisticsSystem
Export-ModuleMember Get-ISIStatisticsHeat

# Non-Exported functions



# Exported Functions
#region Helper Functions
function Disable-CertificateValidation{
<#
.SYNOPSIS
    Disable certificate validation

.DESCRIPTION
    Ignore SSL errors - This would not be used if self signed certificates were not used and the proper CA cert was installed

.EXAMPLE
    Disable-CertificateValidation

.NOTES
    

#>

[CmdletBinding()]

param()

add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;

    public class IDontCarePolicy : ICertificatePolicy {
    public IDontCarePolicy() {}
    public bool CheckValidationResult(
        ServicePoint sPoint, X509Certificate cert,
        WebRequest wRequest, int certProb) {
        return true;
    }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = new-object IDontCarePolicy 

}

function New-PasswordFile{
<#
.SYNOPSIS
    Creates enrypted password file

.DESCRIPTION
    Will prompt for password and write encrypted password to file
    Encryption key is generated based on current windows user security token

.PARAMETER Path
    Path to location of encrypted password file
        Required?                    true 
        Position?                    named
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false

.PARAMETER Filename
    Filename of enrypted password file
        Required?                    true 
        Position?                    named
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false

.INPUTS
    Filename and path
    Will prompt for password to be encrypted

.OUTPUTS
    Encrypted password file

.EXAMPLE
    New-PasswordFile -Path "C:\Temp\Passwords" -Filename "lab-dmuegge-IS7TEST01-PWD.txt"

.NOTES
    This cmdlet is used allow the use of basic authentication and persist authentication info without the use of cookies

#>

	[CmdletBinding()]
	
	param ( 
		[Parameter(Mandatory=$True)][string]$Path, `
		[Parameter(Mandatory=$True)][string]$Filename
	)

    
    Try{
            
        If(Test-Path $Path){
	        $passwd = Read-Host -prompt "Password" -assecurestring
            $FullFilePath = $Path + "\" + $Filename
            New-Item -Path $FullFilePath -ItemType File
	        ConvertFrom-SecureString -securestring $passwd | Out-File -FilePath $FullFilePath.ToString()
        }
        Else
        {
            Write-Error "[New-PasswordFile] :: Path file not found: " $Path
        }

    }
    Catch{
            
        Write-Error $_

    }


}

function Get-PasswordFromFile{
<#
.SYNOPSIS
   Get password from encrypted password file 

.DESCRIPTION
    Will prompt for password and write encrypted password to file
    Encryption key is generated based on current windows user security token

.PARAMETER Path
    Path to location of encrypted password file
        Required?                    true 
        Position?                    named
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false

.PARAMETER Filename
    Filename of enrypted password file
        Required?                    true 
        Position?                    named
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false

.INPUTS
    Filename and path
    
.OUTPUTS
    Encrypted password file

.EXAMPLE
    New-PasswordFile -Path "C:\Temp\Passwords" -Filename "lab-dmuegge-IS7TEST01-PWD.txt"

.NOTES
    This cmdlet is used allow the use of basic authentication and persist authentication info without the use of cookies

#>

	[CmdletBinding()]
	
	param ( 
		[Parameter(Mandatory=$True)][string]$FullPath
	)

    Try{

        # Test file existence and retrieve file object
        If(Test-Path -Path $FullPath){

            $File = Get-item -Path $FullPath
            $filedata = Get-Content -Path $File.FullName
            $password = ConvertTo-SecureString $filedata
            $BSTR = [System.Runtime.InteropServices.marshal]::SecureStringToBSTR($password)
            $password = [System.Runtime.InteropServices.marshal]::PtrToStringAuto($BSTR)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
            return $password

        }
        else
        {
                
            Write-Error "[Get-PasswordFromFile] :: Password file not found: " $FullPath

        }
                        

    }
    Catch{

        Write-Verbose "[Get-PasswordFromFile] :: threw an exception: $_"
        Write-Error $_

    }

    
			
}

Export-ModuleMember Disable-CertificateValidation
Export-ModuleMember New-PasswordFile
Export-ModuleMember Get-PasswordFromFile

#endregion


#region Platform API access
function Set-ISIAPIConnectionInfo{
<#
.SYNOPSIS
    Set Isilon Connection Information
    
.DESCRIPTION
    Stores Isilon platform API connection information

.PARAMETER username
    Platform API username
        Required?                    true 
        Position?                    named
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false

.PARAMETER passwordfile
    Password File for API user
        Required?                    true 
        Position?                    named
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false

.PARAMETER baseurl
    Base URL of Platform API server
        Required?                    true 
        Position?                    named
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false

 
.EXAMPLE
    Set-ISIAPIConnectionInfo -username "Admin" -passwordfile "C:\temp\password.txt" -baseurl "https://testisi.lab.local:8080"

.NOTES
    Password file is created using the New-PasswordFile cmdlet


#>

	[CmdletBinding()]
	
	param ([Parameter(Mandatory=$True)][string]$username,[Parameter(Mandatory=$True)][string]$passwordfile,[Parameter(Mandatory=$True)][string]$baseurl)

    
    

    # Encode basic authorization header
    $upassword = Get-PasswordFromFile -FullPath $passwordfile
    $auth = $username + ':' + $upassword
    $Encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
    $EncodedPassword = [System.Convert]::ToBase64String($Encoded)

    New-Variable -Name ISIAPIBaseURL -Value $baseurl -Scope Global -Force
    New-Variable -Name ISIAPIHeaders -Value @{"Authorization"="Basic $($EncodedPassword)"} -Scope Global -Force

    
			
}

function Set-ISIAPISession{
<#
.SYNOPSIS
    Set Isilon Session
    
.DESCRIPTION
    Stores Isilon platform API connection information

.PARAMETER username
    id of ADS provider to update
        Required?                    true 
        Position?                    named
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false

.PARAMETER passwordfile
    id of ADS provider to update
        Required?                    true 
        Position?                    named
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false

.PARAMETER baseurl
    id of ADS provider to update
        Required?                    true 
        Position?                    named
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false

 
.EXAMPLE
    Set-ISIAPISession -username "Admin" -passwordfile "C:\temp\password.txt" -baseurl "https://testisi.lab.local:8080"

.NOTES
    Password file is created using the New-PasswordFile cmdlet


    THIS IS NOT CURRENTLY WORKING FUNCTIONALITY!


#>

	[CmdletBinding()]
	
	param ([Parameter(Mandatory=$True)][string]$username,[Parameter(Mandatory=$True)][string]$passwordfile,[Parameter(Mandatory=$True)][string]$baseurl)

    
    # Setup base address and objects
    
    $resource = '/session/1/session'
    $url = $baseurl + $resource

    $upassword = Get-PasswordFromFile -FullPath $passwordfile
    $Testcred = (New-Object PSObject |
       Add-Member -PassThru NoteProperty username $username |
       Add-Member -PassThru NoteProperty password $upassword |
       Add-Member -PassThru NoteProperty services ("nfs","smb")
    ) | ConvertTo-JSON

    $response = Invoke-restmethod -Method Post -Uri $url -Body $Testcred -ContentType application/json



    <# 
    # Encode basic authorization header
    $auth = $username + ':' + $upassword
    $Encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
    $EncodedPassword = [System.Convert]::ToBase64String($Encoded)
 #>


    New-Variable -Name ISIAPIBaseURL -Value $baseurl -Scope Global -Force
    New-Variable -Name ISIAPISession -Value $response -Scope Global -Force

    
			
}

function Get-ISICurrentUserToken{
<#
.SYNOPSIS
    Get the security token for the currently authenticated user
    
.DESCRIPTION
    Returns the security token for the currently authenticated user
    
.EXAMPLE
    Get-ISICurrentUserToken

.NOTES

#>

	[CmdletBinding()]
	
	param ()

    # Create full address of resource to be retrieved
    $url = "$ISIAPIBaseURL/platform/1/auth/id"
    

    # Execute request and display SMB Settings
    $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
    $ISIObject.ntoken
	
			
}



Export-ModuleMember Set-ISIAPIConnectionInfo

# THIS IS NOT CURRENTLY WORKING FUNCTIONALITY!
# Export-ModuleMember Set-ISIAPISession
# Export-ModuleMember Get-ISICurrentUserToken
##############################################

#endregion


#region Group Functions

function Get-ISIGroup{
<#
.SYNOPSIS
    Get Isilon group or groups
    
.DESCRIPTION
    Returns Isilon groups

.PARAMETER id
    id of specific group to return <string>
        Required?                    false 
        Position?                    0
        Default value                
        Accept pipeline input?       true
        Accept wildcard characters?  false

.PARAMETER cached
    If true, only return cached objects. <boolean>
        Required?                    false 
        Position?                    named
        Default value                
        Accept pipeline input?       true
        Accept wildcard characters?  false

.PARAMETER domain
    Filter groups by domain. <string>
        Required?                    false 
        Position?                    named
        Default value                
        Accept pipeline input?       true
        Accept wildcard characters?  false

.PARAMETER filter
    Filter groups by name prefix. <string>
        Required?                    false 
        Position?                    named
        Default value                
        Accept pipeline input?       true
        Accept wildcard characters?  false
    
.PARAMETER limit
    Limit number of returned objects. <int>
        Required?                    false 
        Position?                    named
        Default value                
        Accept pipeline input?       true
        Accept wildcard characters?  false

.PARAMETER provider
    Filter groups by provider. <type>[:<name>] <string>
        Required?                    false 
        Position?                    named
        Default value                
        Accept pipeline input?       true
        Accept wildcard characters?  false

.PARAMETER query_member_of
    Enumerate all groups that a group is a member of. <boolean>
        Required?                    false 
        Position?                    named
        Default value                
        Accept pipeline input?       true
        Accept wildcard characters?  false

.PARAMETER resolve_names=<boolean>
    Resolve names of personas.
        Required?                    false 
        Position?                    named
        Default value                
        Accept pipeline input?       true
        Accept wildcard characters?  false

.PARAMETER zone=<string>
    Filter groups by zone.
        Required?                    false 
        Position?                    named
        Default value                
        Accept pipeline input?       true
        Accept wildcard characters?  false

.PARAMETER resume=<string>
    Continue returning results from previous call (cannot be used with other options).
        Required?                    false 
        Position?                    named
        Default value                
        Accept pipeline input?       true
        Accept wildcard characters?  false

.PARAMETER descibe
    switch to View the detailed JSON schema for an authentication group
        Required?                    false 
        Position?                    named
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false
    
.EXAMPLE
    Get-ISIGroup

.EXAMPLE
    Get-ISIGroup -id administrators

.EXAMPLE
    'administrators','users' | Get-ISIGroup

.EXAMPLE
    Get-ISIGroup -describe

.NOTES
    if describe switch is passed other options will be ignored
#>

	[CmdletBinding()]
	
	param ([Parameter(Mandatory=$False,
                      ValueFromPipeline=$true,
                      ValueFromPipelineByPropertyName=$true,
                      Position=0)]$id=$null,
                      [Parameter(Mandatory=$False)]$cached,
                      [Parameter(Mandatory=$False)]$domain,
                      [Parameter(Mandatory=$False)]$filter,
                      [Parameter(Mandatory=$False)]$limit,
                      [Parameter(Mandatory=$False)]$provider,
                      [Parameter(Mandatory=$False)]$query_member_of,
                      [Parameter(Mandatory=$False)]$resolve_names,
                      [Parameter(Mandatory=$False)]$zone,
                      [Parameter(Mandatory=$False)]$resume,
                      [Parameter(Mandatory=$False)][switch]$describe
          )
                      
    
    Begin{
        
    }
    Process{

        # Check if describe parameter passed
        if($describe){
            $url = "$ISIAPIBaseURL/platform/1/auth/groups?describe"
            Write-Verbose -Message "Info: URI - $url"
            $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get
            $ISIObject
        }
        else
        {
            # Check if id parameter passed
            if($id){
                
                # Check if id is simple string
                $queryflag = $false       
                if($id.GetType().Name.ToString() -eq "String" ){

                    # Create request URL and execute
                    $url = "$ISIAPIBaseURL/platform/1/auth/groups/$id"
                    if($cached){if($queryflag){$url += "&cached=$cached"}else{$url += "?cached=$cached"; $queryflag=$true;}}
                    if($domain){if($queryflag){$url += "&domain=$domain"}else{$url += "?domain=$domain"; $queryflag=$true;}}
                    if($filter){if($queryflag){$url += "&filter=$filter"}else{$url += "?filter=$filter"; $queryflag=$true;}}
                    if($limit){if($queryflag){$url += "&limit=$limit"}else{$url += "?limit=$limit"; $queryflag=$true;}}
                    if($provider){if($queryflag){$url += "&provider=$provider"}else{$url += "?provider=$provider"; $queryflag=$true;}}
                    if($query_member_of){if($queryflag){$url += "&query_member_of=$query_member_of"}else{$url += "?query_member_of=$query_member_of"; $queryflag=$true;}}
                    if($resolve_names){if($queryflag){$url += "&resolve_names=$resolve_names"}else{$url += "?resolve_names=$resolve_names"; $queryflag=$true;}}
                    if($zone){if($queryflag){$url += "&zone=$zone"}else{$url += "?zone=$zone"; $queryflag=$true;}}
                    if($resume){if($queryflag){$url += "&resume=$resume"}else{$url += "?resume=$resume"; $queryflag=$true;}}
                    Write-Verbose -Message "Info: URI - $url"
                    $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
                    $ISIObject.groups

                }
                Else
                {
                    # process each object in pipleine
                    foreach($i in $id){
                
                        # Create request URL and execute
                        $idvalue = $i[0].id
                        $url = "$ISIAPIBaseURL/platform/1/auth/groups/$idvalue"
                        if($cached){if($queryflag){$url += "&cached=$cached"}else{$url += "?cached=$cached"; $queryflag=$true;}}
                        if($domain){if($queryflag){$url += "&domain=$domain"}else{$url += "?domain=$domain"; $queryflag=$true;}}
                        if($filter){if($queryflag){$url += "&filter=$filter"}else{$url += "?filter=$filter"; $queryflag=$true;}}
                        if($limit){if($queryflag){$url += "&limit=$limit"}else{$url += "?limit=$limit"; $queryflag=$true;}}
                        if($provider){if($queryflag){$url += "&provider=$provider"}else{$url += "?provider=$provider"; $queryflag=$true;}}
                        if($query_member_of){if($queryflag){$url += "&query_member_of=$query_member_of"}else{$url += "?query_member_of=$query_member_of"; $queryflag=$true;}}
                        if($resolve_names){if($queryflag){$url += "&resolve_names=$resolve_names"}else{$url += "?resolve_names=$resolve_names"; $queryflag=$true;}}
                        if($zone){if($queryflag){$url += "&zone=$zone"}else{$url += "?zone=$zone"; $queryflag=$true;}}
                        if($resume){if($queryflag){$url += "&resume=$resume"}else{$url += "?resume=$resume"; $queryflag=$true;}}
                        Write-Verbose -Message "Info: URI - $url"
                        $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
                        $ISIObject.groups

                    }
            
                }
            }
            else # No parameter passed - return all groups
            {

                # Create request URL and execute
                $url = "$ISIAPIBaseURL/platform/1/auth/groups"
                if($cached){if($queryflag){$url += "&cached=$cached"}else{$url += "?cached=$cached"; $queryflag=$true;}}
                if($domain){if($queryflag){$url += "&domain=$domain"}else{$url += "?domain=$domain"; $queryflag=$true;}}
                if($filter){if($queryflag){$url += "&filter=$filter"}else{$url += "?filter=$filter"; $queryflag=$true;}}
                if($limit){if($queryflag){$url += "&limit=$limit"}else{$url += "?limit=$limit"; $queryflag=$true;}}
                if($provider){if($queryflag){$url += "&provider=$provider"}else{$url += "?provider=$provider"; $queryflag=$true;}}
                if($query_member_of){if($queryflag){$url += "&query_member_of=$query_member_of"}else{$url += "?query_member_of=$query_member_of"; $queryflag=$true;}}
                if($resolve_names){if($queryflag){$url += "&resolve_names=$resolve_names"}else{$url += "?resolve_names=$resolve_names"; $queryflag=$true;}}
                if($zone){if($queryflag){$url += "&zone=$zone"}else{$url += "?zone=$zone"; $queryflag=$true;}}
                if($resume){if($queryflag){$url += "&resume=$resume"}else{$url += "?resume=$resume"; $queryflag=$true;}}
                Write-Verbose -Message "Info: URI - $url"
                $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
                $ISIObject.groups
            
            }
        } # end of no describe switch

    }
    End{

    }
			
}

function Get-ISIGroupMembers{
<#
.SYNOPSIS
    Get Isilon group members
    
.DESCRIPTION
    Returns Isilon group members

.PARAMETER id
    id of specific group to return
        Required?                    true 
        Position?                    0
        Default value                
        Accept pipeline input?       true
        Accept wildcard characters?  false
    
.EXAMPLE
    Get-ISIGroupMembers

.EXAMPLE
    Get-ISIGroupMembers administrators

.EXAMPLE
    Get-ISISGroup | Where id -eq administrators | Get-ISIGroupMembers

.EXAMPLE
    'administrators' | Get-ISIGroupMembers


.NOTES

    

#>

	[CmdletBinding()]
	
	param ([Parameter(Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)]$id)

    Begin{

    }
    Process{      

        # Check if id is simple string
        if(($id.GetType().Name.ToString()) -eq "String"){

            # Create request URL and execute
            $url = "$ISIAPIBaseURL/platform/1/auth/groups/$id/members"
            $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
            $ISIObject.members

        }
        Else
        {
            foreach($i in $id){
                # Create request URL and execute
                $idvalue = $i[0].id
                $url = "$ISIAPIBaseURL/platform/1/auth/groups/$idvalue/members"
                $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
                $ISIObject.members
            }
        } 
	
    }
    End{

    }
			
}

function New-ISIGroup{
<#
.Synopsis
   Create a new isilon group
.DESCRIPTION
   Create a new isilon group
.PARAMETER name
   Name of group
.PARAMETER provider
   Name of authentication provider
.EXAMPLE
   New-ISIGroup -name HRUsers -provider lsa-local-provider:system
.EXAMPLE
   Another example of how to use this cmdlet
.INPUTS
   Inputs to this cmdlet (if any)
.OUTPUTS
   Output from this cmdlet (if any)
.NOTES
   General notes
.COMPONENT
   The component this cmdlet belongs to
.ROLE
   The role this cmdlet belongs to
.FUNCTIONALITY
   The functionality that best describes this cmdlet
#>

    [CmdletBinding(SupportsShouldProcess=$true, 
                   ConfirmImpact='Medium')]
    Param
    (
        # name of group to create
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [Alias("n")] 
        $name,

        # Provider for group being created
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false, 
                   Position=1)]$provider
    )

    Begin
    {

        
        
    }
    Process
    {
        if ($pscmdlet.ShouldProcess("Target", "Operation"))
        {
   
                            
            # Check if id is simple string       
            if($name.GetType().Name.ToString() -eq "String" ){

                # Create request URL and execute
                $url = "$ISIAPIBaseURL/platform/1/auth/groups"
                $JSONObject = (New-Object PSObject | Add-Member -PassThru NoteProperty name $name) 
                if($provider){$JSONObject | Add-Member -PassThru NoteProperty provider $provider}
                $JSONGroup = $JSONObject | ConvertTo-JSON

                Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Post -ContentType application/json -Body $JSONGroup    

            }
            Else  
            {
                # process each object in pipleine
                foreach($i in $name){
                
                    # Create request URL and execute
                    $namevalue = $i[0].name
                    $url = "$ISIAPIBaseURL/platform/1/auth/groups"
                    $JSONObject = (New-Object PSObject | Add-Member -PassThru NoteProperty name $name) 
                    if($provider){$JSONObject | Add-Member -PassThru NoteProperty provider $provider}
                    $JSONGroup = $JSONObject | ConvertTo-JSON

                    Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Post -ContentType application/json -Body $JSONGroup    

                } 
            }
            
        }
    }
    End
    {
        
    }
}

function Remove-ISIGroup{
<#
.Synopsis
   Delete Isilon group
.DESCRIPTION
   Delete Isilon group
.EXAMPLE
   Example of how to use this cmdlet
.EXAMPLE
   Another example of how to use this cmdlet
.INPUTS
   Inputs to this cmdlet (if any)
.OUTPUTS
   Output from this cmdlet (if any)
.NOTES
   General notes
.COMPONENT
   The component this cmdlet belongs to
.ROLE
   The role this cmdlet belongs to
.FUNCTIONALITY
   The functionality that best describes this cmdlet
#>


    
}

function Get-ISINetGroupMembers{
<#
.SYNOPSIS
    Get Isilon netgroup members
    
.DESCRIPTION
    Returns Isilon netgroup members

.PARAMETER netgroup
    netgroup
        Required?                    true 
        Position?                    named
        Default value                
        Accept pipeline input?       true
        Accept wildcard characters?  false
    
.EXAMPLE
    Get-ISINetGroupMembers

.EXAMPLE
    Get-ISINetGroupMembers -netgroup administrators

.NOTES

THE USE OF A NETGROUP DOES NOT APPEAR TO BE DOCUMENTED WELL

#>

	[CmdletBinding()]
	
	param ([Parameter(Mandatory=$True,ValueFromPipeline=$true)]$netgroup)

    Begin{

    }
    Process{

     



        if(($netgroup.GetType().Name) -eq "String"){

            # Create request URL and execute
            $netgroup
            $url = "$ISIAPIBaseURL/platform/1/auth/netgroups/$netgroup"
            $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
            $ISIObject

        }
        Else
        {
            foreach($i in $netgroup){

                $i

                # Create request URL and execute
                $idvalue = $i[0].id
                $url = "$ISIAPIBaseURL/platform/1/auth/netgroups/$idvalue"
                $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
                $ISIObject
            }
        }

    }
    End{

    }
	
			
}


Export-ModuleMember Get-ISIGroup
Export-ModuleMember Get-ISIGroupMembers
Export-ModuleMember New-ISIGroup


# THIS IS NOT CURRENTLY WORKING FUNCTIONALITY and what is a netgroup anyway!
# Export-ModuleMember Get-ISINetGroupMembers
##############################################


#endregion


#region User Functions

function Get-ISIUser{
<#
.SYNOPSIS
    Get Isilon user or users
    
.DESCRIPTION
    Returns Isilon users

.PARAMETER id
    id of specific user to return
        Required?                    false 
        Position?                    0
        Default value                
        Accept pipeline input?       true
        Accept wildcard characters?  false
    
.EXAMPLE
    Get-ISIUser

.EXAMPLE
    Get-ISIUser -id admin

.EXAMPLE
    'admin','root' | Get-ISIUser


.NOTES

#>

	[CmdletBinding()]
	
	param ([Parameter(Mandatory=$False,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)]$id=$null)

    Begin{

    }
    Process{

        # Check if id parameter passed
        if($id){
                
            # Check if id is simple string       
            if($id.GetType().Name.ToString() -eq "String" ){

                # Create request URL and execute
                $url = "$ISIAPIBaseURL/platform/1/auth/users/$id"
                $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
                $ISIObject.users

            }
            Else
            {
                # process each object in pipleine
                foreach($i in $id){
                
                    # Create request URL and execute
                    $idvalue = $i[0].id
                    $url = "$ISIAPIBaseURL/platform/1/auth/users/$idvalue"
                    $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
                    $ISIObject.users

                }
            
            }
        }
        else # No parameter passed - return all users
        {

            # Create request URL and execute
            $url = "$ISIAPIBaseURL/platform/1/auth/users"
            $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
            $ISIObject.users
            
        }

    }
	End{

    }
			
}

function Get-ISIUserMemberOf{
<#
.SYNOPSIS
    Get Isilon groups a user is a member of
    
.DESCRIPTION
    Returns Isilon group membership for a user

.PARAMETER id
    id of specific user to return
        Required?                    true 
        Position?                    0
        Default value                
        Accept pipeline input?       true
        Accept wildcard characters?  false
    
.EXAMPLE
    Get-ISIUserMemberOf

.EXAMPLE
    Get-ISIUserMemberOf admin

.EXAMPLE
    'admin','root' | Get-ISIUserMemberOf

.NOTES

    There appears to be an issue with this API as it does not return data

#>

	[CmdletBinding()]
	
	param ([Parameter(Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)]$id)

    Begin{

    }
    Process{

       # If pipeline input is a single item then execute once with string value
        if(($id.GetType().Name) -eq "String"){

            # Create request URL and execute
            $url = "$ISIAPIBaseURL/platform/1/auth/users/$id/member_of"
            $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
            $ISIObject.member_of

        }
        Else
        {
            # If pipeline input is collection then execute once for each object
            foreach($i in $id){
                
                # Create request URL and execute
                $idvalue = $i[0].id
                $url = "$ISIAPIBaseURL/platform/1/auth/users/$idvalue/member_of"
                $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
                $ISIObject.member_of


            }
        }

    }
    End{

    }
	
			
}

function Get-ISIUserMappingRules{
<#
.SYNOPSIS
    Get the user mapping rules
    
.DESCRIPTION
    Returns the user mapping rules

.EXAMPLE
    Get-ISIUserMappingRules

.NOTES

#>

	[CmdletBinding()]
	
	param ()

    # Create request URL and execute
    $url = "$ISIAPIBaseURL/platform/1/auth/mapping/users/rules"
    $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
    $ISIObject.users
			
}


Export-ModuleMember Get-ISIUser
Export-ModuleMember Get-ISIUserMemberOf
Export-ModuleMember Get-ISIUserMappingRules

#endregion


#region Provider Functions

function Get-ISIProviderSummary{
<#
.SYNOPSIS
    Get Isilon authentication providers
    
.DESCRIPTION
    Returns Isilon authentication providers
 
.EXAMPLE
    Get-ISIProviderSummary

.NOTES

#>

	[CmdletBinding()]
	
	param ()

    # Create full address of resource to be retrieved
    $url = "$ISIAPIBaseURL/platform/1/auth/providers/summary"
    
    # Execute request and display SMB Settings
    $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
    $ISIObject.provider_instances
	
}


#region ADS Provider Functions

function Get-ISIADSProvider{
<#
.SYNOPSIS
    Get Isilon ADS authentication providers
    
.DESCRIPTION
    Returns Isilon ADS authentication providers

.PARAMETER id
    id of specific provider
        Required?                    false 
        Position?                    0
        Default value                
        Accept pipeline input?       true
        Accept wildcard characters?  false
 
.EXAMPLE
    Get-ISIADSProvider

.EXAMPLE
    Get-ISIADSProvider -id DOMAIN.LOCAL

.EXAMPLE
    'DOMAIN.LOCAL','TST.DOMAIN.LOCAL' | Get-ISIADSProvider

.NOTES
    This does not return data when using a parameter. Problem with Isilon API?

#>

	[CmdletBinding()]
	
	param ([Parameter(Mandatory=$False,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)]$id=$null)

    Begin{

    }
    Process{

        # Check if id parameter passed
        if($id){

            # If pipeline input is a single item then execute once with string value
            if(($id.GetType().Name) -eq "String"){

                # Create request URL and execute
                $url = "$ISIAPIBaseURL/platform/1/auth/providers/ads/$id"
                $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
                $ISIObject.ads

            }
            Else
            {
                # If pipeline input is collection then execute once for each object
                foreach($i in $id){
                
                    # Create request URL and execute
                    $idvalue = $i[0].id
                    $url = "$ISIAPIBaseURL/platform/1/auth/providers/ads/$idvalue"
                    $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
                    $ISIObject.ads

                }
            }

        }
        else # No parameter passed - return all ads providers
        {

            # Create request URL and execute
            $url = "$ISIAPIBaseURL/platform/1/auth/providers/ads"
            $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
            $ISIObject.ads
            
        }


    }
    End{

    }
	
			
}

function Set-ISIADSProvider{
<#
.SYNOPSIS
    Set Isilon ADS authentication providers
    
.DESCRIPTION
    Updatess Isilon ADS authentication providers

.PARAMETER id
    id of ADS provider to update
        Required?                    true 
        Position?                    named
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false
 
.EXAMPLE
    Set-ISIADSProvider

.EXAMPLE
    Set-ISIADSProvider -id DOMAIN.LOCAL

.NOTES

    UNTESTED FUNCTIONALITY!

#>

	[CmdletBinding()]
	
	param ([Parameter(Mandatory=$True)][string]$id)

    # Create full address of resource to be retrieved
    $url = "$ISIAPIBaseURL/platform/1/auth/providers/ads/$id"
    
    # Execute request and display SMB Settings
    $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
    $ISIObject.ads
	
			
}

function Set-ISIADSJoinDomain{
<#
.SYNOPSIS
    Join Isilon cluster to AD Domain
    
.DESCRIPTION
    Join Isilon cluster to AD Domain
 
.EXAMPLE
    Set-ISIADSJoinDomain

.NOTES

    UNTESTED FUNCTIONALITY!

#>

	[CmdletBinding()]
	
	param ()

    # Create full address of resource to be retrieved
    $url = "$ISIAPIBaseURL/platform/1/auth/providers/ads"
    
    
    # Execute request and display SMB Settings
    $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Post 
    $ISIObject
			
}

function Set-ISIADSLeaveDomain{
<#
.SYNOPSIS
    Remove Isilon cluster from AD Domain
    
.DESCRIPTION
    Removes Isilon cluster from AD Domain

.PARAMETER id
    id of domain
        Required?                    true 
        Position?                    named
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false
 
.EXAMPLE
    

.NOTES

    UNTESTED FUNCTIONALITY!

#>

	[CmdletBinding()]
	
	param ([Parameter(Mandatory=$True)][string]$id)

    # Create full address of resource to be retrieved
    $url = "$ISIAPIBaseURL/platform/1/auth/providers/ads/$id"
    
    
    # Execute request and display SMB Settings
    $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Put 
    $ISIObject
			
}

function Get-ISIADSTrustedDomains{
<#
.SYNOPSIS
    Get trusted domains for ADS authentication provider
    
.DESCRIPTION
    Returns trusted domains for ADS authentication provider

.PARAMETER id
    id of ADS authentication provider
        Required?                    true 
        Position?                    named
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false

.PARAMETER adsdomain
    name of trusted domain
        Required?                    true 
        Position?                    named
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false
     
.EXAMPLE
    Get-ISIADSTrustedDomains -id DOMAIN.LOCAL -adsdomain

.NOTES

#>

	[CmdletBinding()]
	
	param ([Parameter(Mandatory=$True)][string]$id,[Parameter(Mandatory=$True)][String]$adsdomain)

    # Create full address of resource to be retrieved
    $url = "$ISIAPIBaseURL/platform/1/auth/providers/ads/$id/domains/$adsdomain"
    
    # Execute request and display SMB Settings
    $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
    $ISIObject.Domains
	
			
}

function Get-ISIADSProviderDomainControllers{
<#
.SYNOPSIS
    Get all domain controllers for a trusted domain
    
.DESCRIPTION
    Returns all domain controllers for a trusted domain

.PARAMETER id
    id of specific domain
        Required?                    true 
        Position?                    0
        Default value                
        Accept pipeline input?       true
        Accept wildcard characters?  false
 
.EXAMPLE
    Get-ISIADSProviderDomainControllers DOMAIN.LOCAL

.EXAMPLE
    Get-ISIADSProviderDomainControllers -id DOMAIN.LOCAL



.NOTES

#>

	[CmdletBinding()]
	
	param([Parameter(Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)]$id)

    Begin{

    }
    Process{

        
        # If pipeline input is a single item then execute once with string value
        if(($id.GetType().Name) -eq "String"){

            # Create request URL and execute
            $url = "$ISIAPIBaseURL/platform/1/auth/providers/ads/$id/controllers"
            $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
            $ISIObject.controllers

        }
        Else
        {
            # If pipeline input is collection then execute once for each object
            foreach($i in $id){
                
                # Create request URL and execute
                $idvalue = $i[0].id
                $url = "$ISIAPIBaseURL/platform/1/auth/providers/ads/$idvalue/controllers"
                $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
                $ISIObject.controllers

            }
        }
	
    }
			
}

#endregion


#region File Provider Functions

function Get-ISIFileProvider{
<#
.SYNOPSIS
    Get Isilon File authentication providers
    
.DESCRIPTION
    Returns Isilon File authentication providers

.PARAMETER id
    id of specific provider
        Required?                    false 
        Position?                    named
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false
 
.EXAMPLE
    Get-ISIFileProvider

.EXAMPLE
    Get-ISIFileProvider -id System

.EXAMPLE
    'System' | Get-ISIFileProvider

.NOTES

#>

	[CmdletBinding()]
	
	param ([Parameter(Mandatory=$False,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$id=$null)


    # Check if id parameter passed
    if($id){

        # If pipeline input is a single item then execute once with string value
        if(($id.GetType().Name) -eq "String"){

            # Create request URL and execute
            $url = "$ISIAPIBaseURL/platform/1/auth/providers/file/$id"
            $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
            $ISIObject.file

        }
        Else
        {
            # If pipeline input is collection then execute once for each object
            foreach($i in $id){
                
                # Create request URL and execute
                $idvalue = $i[0].id
                $url = "$ISIAPIBaseURL/platform/1/auth/providers/file/$idvalue"
                $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
                $ISIObject.file

            }
        }

    }
    else # No parameter passed - return all ads providers
    {

        # Create request URL and execute
        $url = "$ISIAPIBaseURL/platform/1/auth/providers/file"
        $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
        $ISIObject.file
            
    }
			
}

#endregion


Export-ModuleMember Get-ISIProviderSummary

# ADS Provider
Export-ModuleMember Get-ISIADSProvider
# Export-ModuleMember Set-ISIADSProvider    # UNTESTED FUNCTIONALITY!
# Export-ModuleMember Set-ISIADSJoinDomain  # UNTESTED FUNCTIONALITY!
# Export-ModuleMember Set-ISIADSLeaveDomain # UNTESTED FUNCTIONALITY!
Export-ModuleMember Get-ISIADSTrustedDomains
Export-ModuleMember Get-ISIADSProviderDomainControllers


# File Provider
Export-ModuleMember Get-ISIFileProvider

#endregion


#region NFS Functions

function Get-ISINFSSettings{
<#
.SYNOPSIS
    Get Isilon NFS Protocol Settings
    
.DESCRIPTION
    Returns cluster NFS protocol settings    

.EXAMPLE
    Get-ISINFSSettings

.NOTES

#>

	[CmdletBinding()]
	
	param ()

    # Create full address of resource to be retrieved
    $url = "$ISIAPIBaseURL/platform/1/protocols/nfs/settings/global"    

    # Execute request and display SMB Settings
    $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
    $ISIObject.settings
	
			
}

function Get-ISINFSExportsSummary{
<#
.SYNOPSIS
    Get Isilon NFS exports summary
    
.DESCRIPTION
    Returns Isilon NFS exports summary
 
.EXAMPLE
    Get-ISINFSExportsSummary

.NOTES

#>

	[CmdletBinding()]
	
	param()

    # Create full address of resource to be retrieved
    $url = "$ISIAPIBaseURL/platform/1/protocols/nfs/exports-summary"
    
    
    # Execute request and display SMB Settings
    $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
    $ISIObject.exports
	
}

function Get-ISINFSExports{
<#
.SYNOPSIS
    Get Isilon NFS exports
    
.DESCRIPTION
    Returns Isilon NFS exports

.PARAMETER id
    id of export
        Required?                    false 
        Position?                    0
        Default value                
        Accept pipeline input?       true
        Accept wildcard characters?  false
 
.EXAMPLE
    Get-ISINFSExports

.EXAMPLE
    Get-ISINFSExports -id Test

.EXAMPLE
    'ifs' | Get-ISINFSExports


.NOTES

#>

	[CmdletBinding()]
	
	param ([Parameter(Mandatory=$False,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)][string]$id=$null)

    Begin{

    }
    Process{
    
        # Check if id parameter passed
        if($id){

            # If pipeline input is a single item then execute once with string value
            if(($id.GetType().Name) -eq "String"){

                # Create request URL and execute
                $url = "$ISIAPIBaseURL/platform/1/protocols/nfs/exports/$id"
                $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
                $ISIObject.exports

            }
            Else
            {
                # If pipeline input is collection then execute once for each object
                foreach($i in $id){
                
                    # Create request URL and execute
                    $idvalue = $i[0].id
                    $url = "$ISIAPIBaseURL/platform/1/protocols/nfs/exports/$idvalue"
                    $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
                    $ISIObject.exports

                }
            }

        }
        else # No parameter passed - return all ads providers
        {

            # Create request URL and execute
            $url = "$ISIAPIBaseURL/platform/1/protocols/nfs/exports"
            $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
            $ISIObject.exports
            
        }

    }
    End{

    }
	
}


Export-ModuleMember Get-ISINFSExportsSummary
Export-ModuleMember Get-ISINFSExports
Export-ModuleMember Get-ISINFSSettings


#endregion


#region SMB Functions

function Get-ISISMBSettings{
<#
.SYNOPSIS
    Get Isilon SMB Protocol Settings
    
.DESCRIPTION
    Returns cluster SMB protocol settings    

.EXAMPLE
    Get-ISISMBSettings

.NOTES

#>

	[CmdletBinding()]
	
	param ()

    # Create full address of resource to be retrieved
    $url = "$ISIAPIBaseURL/platform/1/protocols/smb/settings/global"

    # Execute request and display SMB Settings
    $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
    $ISIObject.settings
	
			
}

function Get-ISISMBSharesSummary{
<#
.SYNOPSIS
    Get Isilon SMB Shares summary
    
.DESCRIPTION
    Returns Isilon SMB Shares summary
 
.EXAMPLE
    Get-ISISMBSharesSummary

.NOTES

#>

	[CmdletBinding()]
	
	param()

    # Create full address of resource to be retrieved
    $url = "$ISIAPIBaseURL/platform/1/protocols/smb/shares-summary"
    
    
    # Execute request and display SMB Settings
    $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
    $ISIObject.shares
	
}

function Get-ISISMBShare{
<#
.SYNOPSIS
    Get Isilon SMB Shares
    
.DESCRIPTION
    Returns Isilon SMB Shares

.PARAMETER sharename
    name of share
        Required?                    false 
        Position?                    0
        Default value                
        Accept pipeline input?       true
        Accept wildcard characters?  false
 
.EXAMPLE
    Get-ISISMBShares

.EXAMPLE
    Get-ISISMBShares -sharename ifs

.EXAMPLE
    'ifs' | Get-ISISMBShares


.NOTES

#>

	[CmdletBinding()]
	
	param ([Parameter(Mandatory=$False,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)]$sharename=$null)

    Begin{

    }
    Process{
    
        # Check if id parameter passed
        if($sharename){

            # If pipeline input is a single item then execute once with string value
            if(($sharename.GetType().Name) -eq "String"){

                # Create request URL and execute
                $url = "$ISIAPIBaseURL/platform/1/protocols/smb/shares/$sharename"
                $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
                $ISIObject.shares

            }
            Else
            {
                # If pipeline input is collection then execute once for each object
                foreach($i in $sharename){
                
                    # Create request URL and execute
                    $idvalue = $i[0].id
                    $url = "$ISIAPIBaseURL/platform/1/protocols/smb/shares/$idvalue"
                    $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
                    $ISIObject.shares

                }
            }

        }
        else # No parameter passed - return all SMB shares
        {

            # Create request URL and execute
            $url = "$ISIAPIBaseURL/platform/1/protocols/smb/shares"
            $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
            $ISIObject.shares
            
        }


    }
    End{

    }
	
}

function Get-ISISMBOpenFiles{
<#
.SYNOPSIS
    Get Isilon SMB Open Files
    
.DESCRIPTION
    Returns Isilon SMB Open Files

.EXAMPLE
    Get-ISISMBOpenFiles

.NOTES

#>

	[CmdletBinding()]
	
	param ()

    # Create full address of resource to be retrieved
    $url = "$ISIAPIBaseURL/platform/1/protocols/smb/openfiles"
    
    # Execute request and display SMB Settings
    $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
    $ISIObject.openfiles
	
}

function Get-ISISMBSessions{
<#
.SYNOPSIS
    Get Isilon SMB Sessions
    
.DESCRIPTION
    Returns Isilon SMB Sessions

.EXAMPLE
    Get-ISISMBSessions

.NOTES

#>

	[CmdletBinding()]
	
	param ()

    # Create full address of resource to be retrieved
    $url = "$ISIAPIBaseURL/platform/1/protocols/smb/sessions"
    
    # Execute request and display SMB Settings
    $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
    $ISIObject.sessions
	
}


function New-ISISMBShare{
<#
.SYNOPSIS
    Create new Isilon SMB Share
    
.DESCRIPTION
    Create new Isilon SMB Share

.PARAMETER sharename
    name of share
        Required?                    false 
        Position?                    0
        Default value                
        Accept pipeline input?       true
        Accept wildcard characters?  false
 
.EXAMPLE
    New-ISISMBShare

.EXAMPLE
    New-ISISMBShare -sharename ifs

.EXAMPLE
    'ifs' | New-ISISMBShare


.NOTES

#>

	[CmdletBinding()]
	
	param ([Parameter(Mandatory=$False,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)]$sharename=$null)

    Begin{

    }
    Process{
    
        # Check if id parameter passed
        if($sharename){

            # If pipeline input is a single item then execute once with string value
            if(($sharename.GetType().Name) -eq "String"){

                # Create request URL and execute
                $url = "$ISIAPIBaseURL/platform/1/protocols/smb/shares/$sharename"
                $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Post 
                $ISIObject.shares

            }
            Else
            {
                # If pipeline input is collection then execute once for each object
                foreach($i in $sharename){
                
                    # Create request URL and execute
                    $idvalue = $i[0].id
                    $url = "$ISIAPIBaseURL/platform/1/protocols/smb/shares/$idvalue"
                    $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Post 
                    $ISIObject.shares

                }
            }

        }
        else # No parameter passed - return all SMB shares
        {

            # Create request URL and execute
            $url = "$ISIAPIBaseURL/platform/1/protocols/smb/shares"
            $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Post 
            $ISIObject.shares
            
        }


    }
    End{

    }
	
}




function Set-ISISMBShare{
<#
.SYNOPSIS
    Set Isilon SMB Share
    
.DESCRIPTION
    Returns Isilon SMB Share(s)

.PARAMETER sharename
    name of share
        Required?                    false 
        Position?                    0
        Default value                
        Accept pipeline input?       true
        Accept wildcard characters?  false
 
.EXAMPLE
    Set-ISISMBShare

.EXAMPLE
    Set-ISISMBShare -sharename ifs

.EXAMPLE
    'ifs' | Set-ISISMBShare


.NOTES

#>

	[CmdletBinding()]
	
	param ([Parameter(Mandatory=$False,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)]$sharename=$null)

    Begin{

    }
    Process{
    
        # Check if id parameter passed
        if($sharename){

            # If pipeline input is a single item then execute once with string value
            if(($sharename.GetType().Name) -eq "String"){

                # Create request URL and execute
                $url = "$ISIAPIBaseURL/platform/1/protocols/smb/shares/$sharename"
                $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
                $ISIObject.shares

            }
            Else
            {
                # If pipeline input is collection then execute once for each object
                foreach($i in $sharename){
                
                    # Create request URL and execute
                    $idvalue = $i[0].id
                    $url = "$ISIAPIBaseURL/platform/1/protocols/smb/shares/$idvalue"
                    $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
                    $ISIObject.shares

                }
            }

        }
        else # No parameter passed - return all SMB shares
        {

            # Create request URL and execute
            $url = "$ISIAPIBaseURL/platform/1/protocols/smb/shares"
            $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
            $ISIObject.shares
            
        }


    }
    End{

    }
	
}



Export-ModuleMember Get-ISISMBSettings
Export-ModuleMember Get-ISISMBSharesSummary
Export-ModuleMember Get-ISISMBShares
Export-ModuleMember Get-ISISMBOpenFiles
Export-ModuleMember Get-ISISMBSessions

#endregion


#region Quota Functions

function Get-ISIQuotaLicense{
<#
.SYNOPSIS
    Get Isilon SmartQuota License Status
    
.DESCRIPTION
    Returns Isilon SmartQuota License Status

.EXAMPLE
    Get-ISIQuotaLicense

.NOTES

#>

	[CmdletBinding()]
	
	param ()

    # Create full address of resource to be retrieved
    $url = "$ISIAPIBaseURL/platform/1/quota/license"
    
    # Execute request and display SMB Settings
    $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
    $ISIObject
	
}

function Get-ISIQuotaSummary{
<#
.SYNOPSIS
    Get Isilon Quota Summary
    
.DESCRIPTION
    Returns Isilon Quota Summary

.EXAMPLE
    Get-ISIQuotaSummary

.NOTES

#>

	[CmdletBinding()]
	
	param ()

    # Create full address of resource to be retrieved
    $url = "$ISIAPIBaseURL/platform/1/quota/quotas-summary"
    
    # Execute request and display SMB Settings
    $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
    $ISIObject.summary
	
}

function Get-ISIQuota{
<#
.SYNOPSIS
    Get Isilon Quotas
    
.DESCRIPTION
    Returns Isilon Quotas

.PARAMETER id
    id of quota
        Required?                    false 
        Position?                    named
        Default value                
        Accept pipeline input?       true
        Accept wildcard characters?  false

.EXAMPLE
    Get-ISIQuota

.EXAMPLE
    Get-ISIQuota

.EXAMPLE
    Get-ISIQuota


.NOTES

#>

	[CmdletBinding()]
	
	param ([Parameter(Mandatory=$False,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Position=0)]$id=$null)

    Begin{

    }
    Process{

        # Check if id parameter passed
        if($id){
                
            # Check if id is simple string       
            if($id.GetType().Name.ToString() -eq "String" ){

                # Create request URL and execute
                $url = "$ISIAPIBaseURL/platform/1/quota/quotas/$id"
                $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
                $ISIObject.quotas

            }
            Else
            {
                # process each object in pipleine
                foreach($i in $id){
                
                    # Create request URL and execute
                    $idvalue = $i[0].id
                    $url = "$ISIAPIBaseURL/platform/1/quota/quotas/$idvalue"
                    $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
                    $ISIObject.quotas

                }
            
            }
        }
        else # No parameter passed - return all users
        {

            # Create request URL and execute
            $url = "$ISIAPIBaseURL/platform/1/quota/quotas"
            $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
            $ISIObject.quotas
            
        }

    }
    End{

    }
	
}

function Get-ISIQuotaNotification{
<#
.SYNOPSIS
    Get Isilon Quota Notification
    
.DESCRIPTION
    Returns Isilon Quota Notification

.PARAMETER quotaid
    id of quota
        Required?                    true 
        Position?                    named
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false

.PARAMETER notificationid
    id of notification
        Required?                    false 
        Position?                    named
        Default value                
        Accept pipeline input?       false
        Accept wildcard characters?  false

.EXAMPLE
    Get-ISIQuota

.NOTES

#>

	[CmdletBinding()]
	
	param ([Parameter(Mandatory=$True)][string]$quotaid,[Parameter(Mandatory=$False)][string]$notificationid=$null)

    # Create full address of resource to be retrieved
    $url = "$ISIAPIBaseURL/platform/1/quota/quotas/$quotaid"
    if($notificationid){$url = $url + "/notifications/" + $notificationid}
    
    # Execute request and display SMB Settings
    $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
    $ISIObject.summary
	
}

function Get-ISIQuotaReport{
<#
.SYNOPSIS
    Get Isilon Quota Report
    
.DESCRIPTION
    Returns Isilon Quota Report

.PARAMETER reportid
    id of report
        Required?                    true 
        Position?                    named
        Default value                
        Accept pipeline input?       true
        Accept wildcard characters?  false

.EXAMPLE
    Get-ISIQuota

.NOTES

#>

	[CmdletBinding()]
	
	param ([Parameter(Mandatory=$False,ValueFromPipeline=$true)][string]$reportid=$null)

    Begin{
    
    }
    Process{

        # Create full address of resource to be retrieved
        $url = "$ISIAPIBaseURL/platform/1/quota/reports"
        if($reportid){$url = $url + "/" + $reportid + "?contents"}
    
    
        # Execute request and display SMB Settings
        $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
        $ISIObject

    }
	End{

    }

}

function Get-ISIQuotaReportAbout{
<#
.SYNOPSIS
    Get Isilon Quota Report About
    
.DESCRIPTION
    Returns Isilon Quota Report About

.PARAMETER reportid
    id of report
        Required?                    true 
        Position?                    named
        Default value                
        Accept pipeline input?       true
        Accept wildcard characters?  false

.EXAMPLE
    Get-ISIQuota

.NOTES

#>

	[CmdletBinding()]
	
	param ([Parameter(Mandatory=$True,ValueFromPipeline=$true)][string]$reportid)

    Begin{

    }
    Process{

        # Create full address of resource to be retrieved
        $url = "$ISIAPIBaseURL/platform/1/quota/reports/$reportid/about"
    
        # Execute request and display SMB Settings
        $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
        $ISIObject

    }
    End{

    }
	
}

function Get-ISIQuotaReportSettings{
<#
.SYNOPSIS
    Get Isilon Quota Report Settings
    
.DESCRIPTION
    Returns Isilon Quota Report Settings

.EXAMPLE
    Get-ISIQuotaReportSettings

.NOTES

#>

	[CmdletBinding()]
	
	param ()

    # Create full address of resource to be retrieved
    $url = "$ISIAPIBaseURL/platform/1/quota/settings/reports"
    
    # Execute request and display SMB Settings
    $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
    $ISIObject
	
}


Export-ModuleMember Get-ISIQuotaLicense
Export-ModuleMember Get-ISIQuotaSummary
Export-ModuleMember Get-ISIQuota
Export-ModuleMember Get-ISIQuotaNotification
Export-ModuleMember Get-ISIQuotaReport
Export-ModuleMember Get-ISIQuotaReportAbout
Export-ModuleMember Get-ISIQuotaReportSettings

#endregion


#region Snapshot Functions

function Get-ISISnapshotLicense{
<#
.SYNOPSIS
    Get Isilon SnapshotIQ License Status
    
.DESCRIPTION
    Returns Isilon SnapshotIQ License Status

.EXAMPLE
    Get-ISISnapshotLicense

.NOTES

#>

	[CmdletBinding()]
	
	param ()

    # Create full address of resource to be retrieved
    $url = "$ISIAPIBaseURL/platform/1/snapshot/license"
    
    # Execute request and display SMB Settings
    $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
    $ISIObject
	
}

function Get-ISISnapshotSummary{
<#
.SYNOPSIS
    Get Isilon Snapshot Summary
    
.DESCRIPTION
    Returns Isilon Snapshot Summary

.EXAMPLE
    Get-ISISnapshotSummary

.NOTES

#>

	[CmdletBinding()]
	
	param ()

    # Create full address of resource to be retrieved
    $url = "$ISIAPIBaseURL/platform/1/snapshot/snapshot-summary"
    
    # Execute request and display SMB Settings
    $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
    $ISIObject.summary
	
}

function Get-ISISnapshot{
<#
.SYNOPSIS
    Get Isilon Snapshot
    
.DESCRIPTION
    Returns Isilon Snapshot

.PARAMETER id
    id of specific user to return
        Required?                    false 
        Position?                    named
        Default value                
        Accept pipeline input?       true
        Accept wildcard characters?  false

.EXAMPLE
    Get-ISISnapshot

.NOTES
    TODO: This get can accept id or snapshot name. Sould use parameter sets

#>

	[CmdletBinding()]
	
	param ([Parameter(Mandatory=$False,ValueFromPipeline=$true)][string]$id=$null)

    Begin{

    }
    Process{

        # Create full address of resource to be retrieved
        $url = "$ISIAPIBaseURL/platform/1/snapshot/snapshots"
    
        # Execute request and display SMB Settings
        $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
        $ISIObject.summary

    }
	End{

    }

}

Export-ModuleMember Get-ISISnapshotLicense
Export-ModuleMember Get-ISISnapshotSummary
Export-ModuleMember Get-ISISnapshot

#endregion


#region Zone Functions

function Get-ISIZone{
<#
.SYNOPSIS
    Get Isilon Zones
    
.DESCRIPTION
    Returns Isilon Zones

.PARAMETER id
    id of zone to return
        Required?                    false 
        Position?                    named
        Default value                
        Accept pipeline input?       true
        Accept wildcard characters?  false

.EXAMPLE
    Get-ISIZones

.NOTES
    

#>

	[CmdletBinding()]
	
	param ([Parameter(Mandatory=$False,ValueFromPipeline=$true)][string]$id=$null)

    Begin{

    }
    Process{
    
    # Create full address of resource to be retrieved
    $url = "$ISIAPIBaseURL/platform/1/zones"
    
    # Execute request and display SMB Settings
    $ISIObject = Invoke-RestMethod -Uri $url -Headers $ISIAPIHeaders -Method Get 
    $ISIObject.zones

    }
    End{

    }
	
}


Export-ModuleMember Get-ISIZone

#endregion



