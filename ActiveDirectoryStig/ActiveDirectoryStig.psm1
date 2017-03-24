#Try to import these, but silently continue on error since another module
#may use this as a dependency, but doesn't have these installed yet
if ((Get-Module -Name ActiveDirectory) -eq $null)
{
	Import-Module -Name ActiveDirectory -ErrorAction SilentlyContinue
}

Function Set-ActiveDirectoryStigItems {
	<#
		.SYNOPSIS
			Executes all of the Active Directory STIG settings included in the module.

		.DESCRIPTION
			The cmdlet runs each audit and configuration setting in the module. It covers items in both the Windows Server Domain Controller STIG and Active Directory STIG. The cmdlet must be run with Enterprise Admin credentials since it sets the configuration for each
			domain in the entire forest of the current user.

		.PARAMETER Credential
			The credentials to run the cmdlet with.

		.INPUTS
			System.Management.Automation.PSCredential

				The input can be piped to Set-ActiveDirectoryStigItems

		.OUTPUTS
			None

        .EXAMPLE
			Set-ActiveDirectoryStigItems

			Configures all of the settings in this module.

		.EXAMPLE
			Set-ActiveDirectoryStigItems -Credential (Get-Credential)

			Configures all of the settings in this module using the specified credentials.

		.NOTES
			This cmdlet must be run with enterprise admin credentials.
			
			AUTHOR: Michael Haken
			LAST UPDATE: 2/27/2016
	#>

	[CmdletBinding()]
	Param(
		[Parameter(Position=0,ValueFromPipeline=$true)] 
		[ValidateNotNull()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty  
	)

	Begin {	
		if (!(Test-IsEnterpriseAdmin -Credential $Credential))
		{
			Write-Warning "The cmdlet must be run with Enterprise Admin credentials."
			Exit 1
		}	
	}

	Process {
		Set-RIDManagerAuditing -Credential $Credential
		Set-PolicyContainerAuditing -Credential $Credential
		Set-MaxConnectionIdleTime -Credential $Credential
		Set-InfrastructureObjectAuditing -Credential $Credential
		Set-DsHeuristics -Credential $Credential
		Set-AdminSDHolderAuditing -Credential $Credential
		Set-DomainAuditing -Credential $Credential
		Set-DomainControllersOUAuditing -Credential $Credential
		Set-NTDSFilePermissions -Credential $Credential
	}

	End {
	}
}

Function Set-NTDSFilePermissions {
	<#
		.SYNOPSIS
			Active Directory data files must have proper access control permissions.

		.DESCRIPTION
			The Set-NTDSFilePermissions cmdlet sets the required security permissions for the database files and log files. The command must be run with Enterprise Admin credentials.

		.PARAMETER Credential
			The credentials to use to make the change. The command must be run with Enterprise Admin credentials.

        .EXAMPLE
			Set-NTDSFilePermissions
	        
			Configures the required permissions for the NTDS database and logs

		.INPUTS
			System.Management.Automation.PSCredential

		.OUTPUTS
			None

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 2/27/2016

		.FUNCTIONALITY

			STIG
				Windows Server 2012 / 2012 R2 Domain Controller V2R3
			STIG ID
				WN12-AD-000001-DC
			Rule ID
				SV-51175r2
			Vuln ID
				V-8316
			Severity
				CAT I
	#>

	[CmdletBinding()]
	Param(
		[Parameter(Position=0,ValueFromPipeline=$true)] 
		[ValidateNotNull()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty  
	)

    Begin {	
		if (!(Test-IsEnterpriseAdmin -Credential $Credential))
		{
			Write-Error "The cmdlet must be run with Enterprise Admin credentials."
			Exit 1
		}
    }

    Process
    {
        $BuiltinAdministrators = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
        $System = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
        $CreatorOwner = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::CreatorOwnerSid, $null)
        $LocalService = New-Object Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalServiceSid, $null)

        $AdministratorAce = New-Object System.Security.AccessControl.FileSystemAccessRule($BuiltinAdministrators,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow       
        )

        $SystemAce = New-Object System.Security.AccessControl.FileSystemAccessRule($System,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )

        $CreatorOwnerAce = New-Object System.Security.AccessControl.FileSystemAccessRule($CreatorOwner,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            @([System.Security.AccessControl.InheritanceFlags]::ObjectInherit, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )

        $LocalServiceAce = New-Object System.Security.AccessControl.FileSystemAccessRule($LocalService,
            @([System.Security.AccessControl.FileSystemRights]::AppendData, [System.Security.AccessControl.FileSystemRights]::CreateDirectories),
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )

		([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).Domains | ForEach-Object {
			$_.DomainControllers | Select-Object -ExpandProperty Name | ForEach-Object {
				Write-Host ("Reviewing Domain Contoller " + $_)
				$NTDS = Invoke-Command -ScriptBlock { Get-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Services\\NTDS\\Parameters" } -ComputerName $_
				$DSA = $NTDS.'DSA Database File'
				$Logs = $NTDS.'Database log files path'
				$DSA = "\\$_\\" + $DSA.Replace(":\","$\").Replace("\", "\\")
				$Logs = "\\$_\\" + $Logs.Replace(":\","$\").Replace("\", "\\")

				$DSA = $DSA.Substring(0, $DSA.LastIndexOf("\\"))

				$ACL1 = Get-Acl -Path $DSA

				foreach ($Rule in $ACL1.Access) {
					$ACL1.RemoveAccessRule($Rule) | Out-Null
				}

				$ACL1.AddAccessRule($AdministratorAce)
				$ACL1.AddAccessRule($SystemAce)

				Write-Host "Setting $DSA ACL"

				Set-Acl -Path $DSA -AclObject $ACL1

				Get-ChildItem -Path $DSA | ForEach-Object {
					$Acl = Get-Acl -Path $_.FullName

					foreach ($Rule in $Acl.Access) {
						if (-not $Rule.IsInherited) {
							$Acl.RemoveAccessRule($Rule) | Out-Null
						}
					}

					Set-Acl -Path $_.FullName -AclObject $Acl
				}

				$ACL2 = Get-Acl -Path $Logs

				foreach ($Rule in $ACL2.Access)
				{
					$ACL2.RemoveAccessRule($Rule) | Out-Null
				}

				$ACL2.AddAccessRule($AdministratorAce)
				$ACL2.AddAccessRule($SystemAce)
				$ACL2.AddAccessRule($LocalServiceAce)
				$ACL2.AddAccessRule($CreatorOwnerAce)

				Write-Host "Setting $Logs ACL"

				Set-Acl -Path $Logs -AclObject $ACL2

				Get-ChildItem -Path $Logs | ForEach-Object {
					$Acl = Get-Acl -Path $_.FullName

					foreach ($Rule in $Acl.Access) {
						if (-not $Rule.IsInherited) {
							$Acl.RemoveAccessRule($Rule) | Out-Null
						}
					}

					Set-Acl -Path $_.FullName -AclObject $Acl
				}
			}
		}
	}

    End {
	}
}

Function Set-RIDManagerAuditing {
	<#
		.SYNOPSIS
			The Active Directory RID Manager$ object must be configured with proper audit settings.

		.DESCRIPTION
			The Set-RIDManagerAuditing cmdlet sets the required auditing. The command must be run with Enterprise Admin credentials.

		.PARAMETER Credential
			The credentials to use to make the change. The command must be run with Enterprise Admin credentials.
		
        .EXAMPLE
			Set-RIDManagerAuditing

	        Configures the required auditing for the RID Manager object.

		.INPUTS
			System.Management.Automation.PSCredential

		.OUTPUTS
			None

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 2/27/2016
		
		.FUNCTIONALITY
			STIG
				Windows Server 2012 / 2012 R2 Domain Controller V2R3
			STIG ID
				WN12-AU-000212-DC
			Rule ID
				SV-51174r2
			Vuln ID
				V-39330
			Severity
				CAT II
	#>

	[CmdletBinding()]
	Param(
		[Parameter(Position=0,ValueFromPipeline=$true)] 
		[ValidateNotNull()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty  
	)
	Begin {
		if (!(Test-IsEnterpriseAdmin -Credential $Credential))
		{
			Write-Error "The cmdlet must be run with Enterprise Admin credentials."
			Exit 1
		}
	}

	Process
	{
		$Domains = Get-ForestDomains
		foreach ($Domain in $Domains)
		{
			[System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-RIDManagerAuditRuleSet
			Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "CN=RID Manager$,CN=System"
		}
	}

	End {
	}
}

Function Set-PolicyContainerAuditing {
	<#
		.SYNOPSIS
			Active Directory Group Policy objects must be configured with proper audit settings.

		.DESCRIPTION
			The Set-PolicyContainerAuditing cmdlet sets the required auditing. The command must be run with Enterprise Admin credentials.

		.PARAMETER Credential
			The credentials to use to make the change. The command must be run with Enterprise Admin credentials.

        .EXAMPLE
			Set-PolicyContainerAuditing

	        Configures the required auditing for the Group Policy container.

		.INPUTS
			None

		.OUTPUTS
			None

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 2/27/2016

		.FUNCTIONALITY
			STIG
				Windows Server 2012 / 2012 R2 Domain Controller V2R3
			STIG ID
				WN12-AU-000207-DC
			Rule ID
				SV-51169r4
			Vuln ID
				V-39325
			Severity
				CAT II
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Position=0,ValueFromPipeline=$true)] 
		[ValidateNotNull()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty  
	)

	Begin {
		if (!(Test-IsEnterpriseAdmin -Credential $Credential))
		{
			Write-Error "The cmdlet must be run with Enterprise Admin credentials."
			Exit 1
		}
	}

	Process
	{
		$Domains = Get-ForestDomains
		foreach ($Domain in $Domains)
		{
			[System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-PolicyContainerAuditRuleSet
			Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "CN=Policies,CN=System"
		}
	}

	End {
	}
}

Function Set-MaxConnectionIdleTime {
	<#
		.SYNOPSIS
			The directory service must be configured to terminate LDAP-based network connections to the directory server after five (5) minutes of inactivity.
		
		.DESCRIPTION
			The Set-MaxConnectionIdleTime cmdlet sets the timeout for inactive connections. The command must be run with Enterprise Admin credentials.

		.PARAMETER MaxConnIdleTime
			The timeout for inactive network connections. Defaults to 5 minutes.

		.PARAMETER Credential
			The credentials to use to make the change. The command must be run with Enterprise Admin credentials.
		
        .EXAMPLE
			Set-MaxConnectionIdleTime

	        Sets the connection idle time setting to 5 minutes (default).

		.EXAMPLE
			Set-MaxConnectionIdleTime -MaxConnIdleTime 180

			Sets the connection idle time setting to 3 minutes
		
		.INPUTS
			System.Int32

		.OUTPUTS
			System.String

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 2/27/2016

		.FUNCTIONALITY
			STIG
				Windows Server 2012 / 2012 R2 Domain Controller V2R3
			STIG ID
				WN12-AD-000014-DC
			Rule ID
				SV-51188r2
			Vuln ID
				V-14831
			Severity
				CAT III
	#>
	[CmdletBinding()]
	Param
	(   
		[Parameter(Position=0, ValueFromPipeline=$true)] 
		[ValidateScript({
			$_ -gt 0
		})]
		[System.Int32]$MaxConnIdleTime = 300,

		[Parameter(Position=1)] 
		[ValidateNotNull()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty  
	)

	Begin {
		if (!(Test-IsEnterpriseAdmin -Credential $Credential))
		{
			Write-Warning "The cmdlet must be run with Enterprise Admin credentials."
			Exit 1
		}
	}

	Process
	{
		[string]$DomainDN = [System.String]::Empty

		if ([System.Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) {
			$Role = Get-WmiObject -Class Win32_OperatingSystem -Property ProductType | Select-Object -ExpandProperty ProductType
			if ($Role -eq 2) {
				$DomainDN = Get-ADDomain -Identity (Get-ADForest -Current LoggedOnUser -Server $env:COMPUTERNAME).RootDomain -Server $env:COMPUTERNAME | Select-Object -ExpandProperty DistinguishedName
			}
		}

		if ([System.String]::IsNullOrEmpty($DomainDN)) {
			$DomainDN = Get-ADDomain -Identity (Get-ADForest -Current LoggedOnUser).RootDomain | Select-Object -ExpandProperty DistinguishedName
		}

		[string]$SearchBase = "CN=Query-Policies,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + $DomainDN
		[Microsoft.ActiveDirectory.Management.ADEntity]$Policies = get-adobject -SearchBase $SearchBase -Filter 'ObjectClass -eq "queryPolicy" -and Name -eq "Default Query Policy"' -Properties *
		$AdminLimits = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]$Policies.lDAPAdminLimits

		for ($i = 0; $i -lt $AdminLimits.Count; $i++)
		{
			if ($AdminLimits[$i] -match "MaxConnIdleTime=*")
			{
				break
			}
		}   

		if ($i -lt $AdminLimits.Count)
		{
			$AdminLimits[$i] = "MaxConnIdleTime=$MaxConnIdleTime" 
		}
		else
		{
			$AdminLimits.Add("MaxConnIdleTime=$MaxConnIdleTime")
		}

		if ($Credential -ne [System.Management.Automation.PSCredential]::Empty -and $Credential -ne $null)
		{
			Set-ADObject -Identity $Policies -Clear lDAPAdminLimits -Credential $Credential

			foreach ($Limit in $AdminLimits)
			{
				Set-ADObject -Identity $Policies -Add @{lDAPAdminLimits=$Limit} -Credential $Credential
			}
		}
		else
		{
			Set-ADObject -Identity $Policies -Clear lDAPAdminLimits

			foreach ($Limit in $AdminLimits)
			{
				Set-ADObject -Identity $Policies -Add @{lDAPAdminLimits=$Limit}
			}
		}

		Write-Output -InputObject (Get-ADObject -Identity $Policies -Properties * | Select-Object -ExpandProperty lDAPAdminLimits | Where-Object {$_ -match "MaxConnIdleTime=*"})
	}

	End {	
	}
}

Function Set-InfrastructureObjectAuditing {
	<#
		.SYNOPSIS
			The Active Directory Infrastructure object must be configured with proper audit settings.

		.DESCRIPTION
			The Set-InfrastructureObjectAuditing cmdlet sets the required auditing. The command must be run with Enterprise Admin credentials.

		.PARAMETER Credential
			The credentials to use to make the change. The command must be run with Enterprise Admin credentials.

        .EXAMPLE
			Set-InfrastructureObjectAudting

	        Configures the required auditing for the infrastructure object.

		.INPUTS
			System.Management.Automation.PSCredential

		.OUTPUTS
			None

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 12/5/2015
		
		.FUNCTIONALITY
			STIG
				Windows Server 2012 / 2012 R2 Domain Controller V2R3
			STIG ID
				WN12-AU-000209-DC
			Rule ID
				SV-51171r2
			Vuln ID
				V-39327
			Severity
				CAT II
	#>
	[CmdletBinding()]
	Param(
		[Parameter(Position=0,ValueFromPipeline=$true)] 
		[ValidateNotNull()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty  
	)

	Begin {
		if (!(Test-IsEnterpriseAdmin -Credential $Credential))
		{
			Write-Error "The cmdlet must be run with Enterprise Admin credentials."
			Exit 1
		}
	}

	Process
	{
		$Domains = Get-ForestDomains

		foreach ($Domain in $Domains)
		{
			[System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-InfrastructureObjectAuditRuleSet
			Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "CN=Infrastructure"
		}
	}

	End {
	}
}

Function Set-DsHeuristics {
	<#
		.SYNOPSIS
			The dsHeuristics option can be configured to override the default restriction on anonymous access to AD data above the rootDSE level. Directory data (outside the root DSE) of a non-public directory must be configured to prevent anonymous access.

		.DESCRIPTION
			The Set-DsHeuristics cmdlet configures anonymous access to AD data. The command must be run with Enterprise Admin credentials.
	
		.PARAMETER AddAnonymousAccess	
			Adds anonymous read access to the AD Forest

		.PARAMETER Credential
			The credentials to use to make the change. The command must be run with Enterprise Admin credentials.

		.EXAMPLE
			Set-DsHeuristic

	        Removes anonymous access from the AD Forest
		
		.EXAMPLE
			Set-DsHeuristic -AddAnonymousRead

			Adds anonymous read access to the AD Forest
			
		.INPUTS
			System.Management.Automation.SwitchParameter, System.Management.Automation.PSCredential		

		.OUTPUTS
			System.String

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 2/27/2016
		
		.FUNCTIONALITY
			STIG
				Active Directory Forest V2R5 1/23/2015
				Windows Server 2012 / 2012 R2 Domain Controller V2R3
			STIG ID
				AD.0230
				WN12-AD-000013-DC
			Rule ID
				SV-9052r2
				SV-52838r1
			Vuln ID
				V-8555
				V-1070
			Severity
				CAT II
	#>
	[CmdletBinding()]
	Param
	(
		[Parameter()] 
		[switch]$AddAnonymousRead,

		[Parameter()] 
		[ValidateNotNull()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty
	)

	Begin
    {
		if (!(Test-IsEnterpriseAdmin -Credential $Credential))
		{
			Write-Error "The cmdlet must be run with Enterprise Admin credentials."
			Exit 1
		}
    }

    Process
    { 
        $DN = ("CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration," + (Get-ADDomain -Identity (Get-ADForest -Current LocalComputer).RootDomain).DistinguishedName)
        $DirectoryService = Get-ADObject -Identity $DN -Properties dsHeuristics
        [string]$Heuristic = $DirectoryService.dsHeuristics

        [array]$Array = @()
        if ($AddAnonymousRead)
        {
            if($Heuristic -ne $null -and $Heuristic -ne [System.String]::Empty)
            {
                $Array = $Heuristic.ToCharArray()
                if ($Array.Length -lt 7)
                {
                    for ($i = $Array.Length; $i -lt 6; $i++)
                    {
                        $Array += "0"
                    }

                    $Array += "2"
                }
                else
                {
                    $Array[6] = "2"
                }
            }
            else
            {
                $Array = "0000002"
            }
        }
        else
        {
            if (($Heuristic -ne $null) -and ($Heuristic -ne [System.String]::Empty) -and ($Heuristic.Length -ge 7))
            {
                $Array = $Heuristic.ToCharArray()
                $Array[6] = "0";
            }
			else
			{
				$Array = "0000000"
			}
        }

        [string]$Heuristic = "$Array".Replace(" ", [System.String]::Empty)
        if ($Heuristic -ne $null -and $Heuristic -ne [System.String]::Empty)
        {
            if ($Credential -ne [System.Management.Automation.PSCredential]::Empty -and $Credential -ne $null)
            {
                Set-ADObject -Identity $DirectoryService -Replace @{dsHeuristics = $Heuristic} -Credential $Credential
            }
            else
            {
                Set-ADObject -Identity $DirectoryService -Replace @{dsHeuristics = $Heuristic}
            }
        }

		$Result = Get-ADObject -Identity $DirectoryService -Properties dsHeuristics | Select-Object -ExpandProperty dsHeuristics
        if ($Result -ne $null)
        {
            Write-Output ("dsHeuristics: " + $Result)
        }
        else
        {
            Write-Warning "dsHeuristics is not set"
			Exit 1
        }
    }

    End {
    }
}

Function Set-DomainControllersOUAuditing {
	<#
		.SYNPOSIS
			The Active Directory Domain Controllers Organizational Unit (OU) object must be configured with proper audit settings.

		.DESCRIPTION
			The Set-DomainControllersOUAuditing cmdlet sets the required auditing. The command must be run with Enterprise Admin credentials.

		.PARAMETER Credential
			The credentials to use to make the change. The command must be run with Enterprise Admin credentials.

        .EXAMPLE
			Set-DomainControllersOUAuditing

	        Configures the required auditing for the domain controller OU.

		.INPUTS
			System.Management.Automation.PSCredential

		.OUTPUTS
			None

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 2/27/2016
		
		.FUNCTIONALITY
			STIG
				Windows Server 2012 / 2012 R2 Domain Controller V2R3
			STIG ID
				WN12-AU-000210-DC
			Rule ID
				SV-51172r2
			Vuln ID
				V-39328
			Severity
				CAT II
	#>

	[CmdletBinding()]
	Param(
		[Parameter(Position=0,ValueFromPipeline=$true)] 
		[ValidateNotNull()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty  
	)

	Begin {
		if (!(Test-IsEnterpriseAdmin -Credential $Credential))
		{
			Write-Error "The cmdlet must be run with Enterprise Admin credentials."
			Exit 1
		}
	}

	Process
	{
		$Domains = Get-ForestDomains

		foreach ($Domain in $Domains)
		{
			[System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-DomainControllersAuditRuleSet
			Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "OU=Domain Controllers"
		}
	}

	End {
	}
}

Function Set-DomainAuditing {
	<#
		.SYNOPSIS
			The Active Directory Domain object must be configured with proper audit settings.

		.DESCRIPTION
			The Set-DomainAuditing cmdlet sets the required auditing. The command must be run with Enterprise Admin credentials.

		.PARAMETER Credential
			The credentials to use to make the change. The command must be run with Enterprise Admin credentials.

        .EXAMPLE
			Set-DomainAudting
	        Configures the required auditing for the domain

		.INPUTS
			System.Management.Automation.PSCredential
		
		.OUTPUTS
			None

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 2/27/2016
		
		.FUNCTIONALITY
			STIG
				Windows Server 2012 / 2012 R2 Domain Controller V2R3
			STIG ID
				WN12-AU-000208-DC
			Rule ID
				SV-51170r2
			Vuln ID
				V-39326
			Severity
				CAT II
	#>

	[CmdletBinding()]
	Param(
		[Parameter(Position=0,ValueFromPipeline=$true)] 
		[ValidateNotNull()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty  
	)

	Begin {
		if (!(Test-IsEnterpriseAdmin -Credential $Credential))
		{
			Write-Error "The cmdlet must be run with Enterprise Admin credentials."
			Exit 1
		}
	}

	Process
	{
		$Domains = Get-ForestDomains

		foreach ($Domain in $Domains)
		{
			[System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-DomainAuditRuleSet -DomainSID (Get-ADDomain -Identity $Domain | Select-Object -ExpandProperty DomainSID)
			Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN ""
		}
	}

	End {}
}

Function Set-AdminSDHolderAuditing {
	<#
		.SYNOPSIS
			The Active Directory AdminSDHolder object must be configured with proper audit settings.

		.DESCRIPTION
			The Set-AdminSDHolderAuditing cmdlet sets the required auditing. The command must be run with Enterprise Admin credentials.

		.PARAMETER Credential
			The credentials to use to make the change. The command must be run with Enterprise Admin credentials.

        .EXAMPLE
			Set-AdminSDHolderAuditing

	        Configures the required auditing for the AdminSDHolder object.

		.INPUTS
			System.Management.Automation.PSCredential

		.OUTPUTS
			None

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 2/27/2016
		
		.FUNCTIONALITY
			STIG
				Windows Server 2012 / 2012 R2 Domain Controller V2R3
			STIG ID
				WN12-AU-000211-DC
			Rule ID
				SV-51173r2
			Vuln ID
				V-39329
			Severity
				CAT II
	#>

	[CmdletBinding()]
	Param(
		[Parameter(Position=0,ValueFromPipeline=$true)] 
		[ValidateNotNull()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty  
	)

    Begin {		
		if (!(Test-IsEnterpriseAdmin -Credential $Credential))
		{
			Write-Error "The cmdlet must be run with Enterprise Admin credentials."
			Exit 1
		}
	}

	Process
    {
		$Domains = Get-ForestDomains

		foreach ($Domain in $Domains)
		{
			[System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = New-EveryoneAuditRuleSet
			Set-Auditing -Domain $Domain -Rules $Rules -ObjectCN "CN=AdminSDHolder,CN=System"
		}
	}
	
	End {
	}	
}

Function Set-Auditing {
	<#
		.SYNOPSIS
			Sets auditing on an Active Directory object.

		.DESCRIPTION
			The Set-Auditing cmdlet applies an audit rule set to an AD object.

		.PARAMETER Domain
			The domain to set the auditing in.

		.PARAMETER ObjectCN
			The CN of the object to set auditing on up to the domain part of the DN. This can be an emptry string to set auditing on the domain.

		.PARAMETER Rules
			The array of ActiveDirectoryAuditRule.

        .EXAMPLE
			Set-Auditing -Domain contoso.com -ObjectCN "CN=Policies,CN=System" -Rules $Rules

	        Implements the audit rules.

		.INPUTS
			System.String, System.String, System.DirectoryServices.ActiveDirectoryAuditRule[], System.Management.Automation.PSCredential

		.OUTPUTS
			None

		.NOTES
			AUTHOR: Michael Haken
			LASTEDIT: 2/27/2016
	#>

	[CmdletBinding()]
    Param 
    (
        [Parameter(Position=0,Mandatory=$true)]
        [string]$Domain,

        [Parameter(Position=1,Mandatory=$true)]
        [AllowEmptyString()]
        [String]$ObjectCN,

        [Parameter(Position=2,Mandatory=$true)]
        [System.DirectoryServices.ActiveDirectoryAuditRule[]]$Rules,

		[Parameter(Position=3)] 
		[ValidateNotNull()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty  
    )

    Begin {
    }

    Process
    {
		$DN = (Get-ADDomain -Identity $Domain).DistinguishedName
		[String[]]$Drives = Get-PSDrive | Select-Object -ExpandProperty Name

        if ($DC -ne $null)
        {
            if (Test-Connection -ComputerName $DC)
            {
                $TempDrive = "tempdrive"

                if ($Drives.Contains($TempDrive))
                {
                    Write-Host "An existing PSDrive exists with name $TempDrive, temporarily removing" -ForegroundColor Yellow
                    $OldDrive = Get-PSDrive -Name $TempDrive
                    Remove-PSDrive -Name $TempDrive
                }

                $Drive = New-PSDrive -Name $TempDrive -Root "" -PSProvider ActiveDirectory -Server $Domain
				Push-Location -Path "$Drive`:\"

                if ($ObjectCN -eq "")
                {
                    $ObjectDN = $DN
                }
                else
                {
                    $ObjectDN = $ObjectCN + "," + $DN
                }

                $ObjectToChange = Get-ADObject -Identity $ObjectDN -Server $Domain

                $Path = $ObjectToChange.DistinguishedName

                try
                {
                    $Acl = Get-Acl -Path $Path -Audit

                    if ($Acl -ne $null)
                    {
                        foreach ($Rule in $Rules)
                        {
                            $Acl.AddAuditRule($Rule)
                        }

                        Set-Acl -Path $Path -AclObject $Acl

                        Write-Results -Path $Path -Domain $Domain
                    }
                    else
                    {
                        Write-Warning "Could not retrieve the ACL for $Path"
                    }
                }
                catch [System.Exception]
                {
                    Write-Warning $_.ToString()
                }

				Pop-Location

                Remove-PSDrive $Drive

                if ($OldDrive -ne $null)
                {
                    Write-Host "Recreating original PSDrive" -ForegroundColor Yellow
                    New-PSDrive -Name $OldDrive.Name -PSProvider $OldDrive.Provider -Root $OldDrive.Root | Out-Null
                    $OldDrive = $null
                }
            }
            else
            {
                Write-Host "Could not contact domain controller $DC" -ForegroundColor Red
            }
        }
    }

    End {
	}
}

Function New-InfrastructureObjectAuditRuleSet {
	<#
		.SYNOPSIS
			Creates the audit rule set for auditing the Infrastructure object.

		.DESCRIPTION
			The New-InfrastructureObjectAuditRuleSet cmdlet creates the required audit rule set for auditing the Infrastructure object.

        .EXAMPLE
			New-InfrastructureObjectAuditRuleSet

	        Creates the audit rules.

		.INPUTS
			None

		.OUTPUTS
			[System.DirectoryServices.ActiveDirectoryAuditRule[]]

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 2/27/2016
	#>

	[CmdletBinding()]
	Param()

	Begin {
	}

	Process
	{
		$Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)

		$EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
			[System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
			[System.Security.AccessControl.AuditFlags]::Failure, 
			[System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

		#$objectguid = "cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd" #Guid for change infrastructure master extended right if it was needed
		$EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
			@([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
			[System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight),
			[System.Security.AccessControl.AuditFlags]::Success,
			[System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

		[System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneSuccess)

		Write-Output -InputObject $Rules
	}

	End {
	}
}

Function New-DomainControllersAuditRuleSet {
	<#
		.SYNOPSIS
			Creates the audit rule set for auditing the domain controller's OU.

		.DESCRIPTION
			The New-DomainControllerAuditRuleSet cmdlet creates the required audit rule set for auditing the Domain Controller's OU.

        .EXAMPLE
			New-DomainControllersAuditRuleSet

	        Creates the audit rules.

		.INPUTS
			None

		.OUTPUTS
			System.DirectoryServices.ActiveDirectoryAuditRule[]

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 2/27/2016
	#>

	[CmdletBinding()]
	Param()

	Begin {
	}

	Process
	{
		$Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)

		$EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
			[System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
			[System.Security.AccessControl.AuditFlags]::Failure, 
			[System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

		$EveryoneWriteDaclSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone, 
			[System.DirectoryServices.ActiveDirectoryRights]::WriteDacl, 
			[System.Security.AccessControl.AuditFlags]::Success, 
			[System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

		$EveryoneWritePropertySuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone, 
			[System.DirectoryServices.ActiveDirectoryRights]::WriteProperty, 
			[System.Security.AccessControl.AuditFlags]::Success, 
			[System.DirectoryServices.ActiveDirectorySecurityInheritance]::All)

		[System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneWriteDaclSuccess, $EveryoneWritePropertySuccess)

		Write-Output -InputObject $Rules
	}

	End {	
	}
}

Function New-EveryoneAuditRuleSet {
	<#
		.SYNOPSIS
			Creates the audit rule set for Everyone success and failures.

		.DESCRIPTION
			The New-EveryoneAuditRuleSet cmdlet creates the an audit rule set for success and failure on Everyone.

        .EXAMPLE
			New-EveryoneAuditRuleSet

	        Creates the audit rules.

		.INPUTS
			None

		.OUTPUTS
			System.DirectoryServices.ActiveDirectoryAuditRule[]

		.NOTES
			AUTHOR: Michael Haken
			LASTEDIT: 2/27/2016
	#>

	[CmdletBinding()]
	Param()

	Begin {
	}

	Process
	{
		$Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)

		$EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone, 
			[System.DirectoryServices.ActiveDirectoryRights]::GenericAll, 
			[System.Security.AccessControl.AuditFlags]::Failure, 
			[System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

		$EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone, 
			@([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty, 
			[System.DirectoryServices.ActiveDirectoryRights]::WriteDacl, 
			[System.DirectoryServices.ActiveDirectoryRights]::WriteOwner),
			[System.Security.AccessControl.AuditFlags]::Success, 
			[System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
        
		[System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneSuccess)

		Write-Output -InputObject $Rules
	}

	End {		
	}
}

Function New-DomainAuditRuleSet {
	<#
		.SYNOPSIS
			Creates the audit rule set for domain object auditing.

		.DESCRIPTION
			The New-DomainAuditRuleSet cmdlet creates the audit rule set for the domain object.

		.PARAMETER DomainSID
			The domain SID object for the domain to associate teh rule set with.

        .EXAMPLE
			New-DomainAuditRuleSet

	        Creates the audit rules.

		.INPUTS
			System.Security.Principal.SecurityIdentifier

		.OUTPUTS
			System.DirectoryServices.ActiveDirectoryAuditRule[]

		.NOTES
			AUTHOR: Michael Haken
			LASTEDIT: 2/27/2016
	#>

	[CmdletBinding()]
	Param
    (
        [Parameter(Position=0,ValueFromPipeline=$true,Mandatory=$true)]
        [System.Security.Principal.SecurityIdentifier]$DomainSID
    )

	Begin {
	}

	Process {  
		$Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)
		$DomainUsers = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::AccountDomainUsersSid, $DomainSID)
		$Administrators = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $DomainSID)

		$EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
			[System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
			[System.Security.AccessControl.AuditFlags]::Failure, 
			[System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

		$DomainUsersSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($DomainUsers, 
			[System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight, 
			[System.Security.AccessControl.AuditFlags]::Success, 
			[System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

		$AdministratorsSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Administrators, 
			[System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight, 
			[System.Security.AccessControl.AuditFlags]::Success, 
			[System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

		$EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone, 
			@([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
			[System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
			[System.DirectoryServices.ActiveDirectoryRights]::WriteOwner), 
			[System.Security.AccessControl.AuditFlags]::Success, 
			[System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

		[System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $DomainUsersSuccess, $AdministratorsSuccess, $EveryoneSuccess)

		Write-Output -InputObject $Rules
	}

	End {
	}
}

Function New-PolicyContainerAuditRuleSet {
	<#
		.SYNOPSIS
			Creates the audit rule set for the Group Policy container.

		.DESCRIPTION
			The New-PolicyContainerAuditRuleSet cmdlet creates the required auditing rule set for group policy objects.

        .EXAMPLE
			New-PolicyContainerAuditRuleSet

	        Creates the audit rules.

		.INPUTS
			None

		.OUTPUTS
			System.DirectoryServices.ActiveDirectoryAuditRule[]

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATED: 2/27/2016
	#>

	[CmdletBinding()]
	Param()

	Begin {
	}

	Process 
	{
		$Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)

		$EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
			[System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
			[System.Security.AccessControl.AuditFlags]::Failure, 
			[System.DirectoryServices.ActiveDirectorySecurityInheritance]::All)
    
		$EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
			@([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
			[System.DirectoryServices.ActiveDirectoryRights]::WriteDacl),
			[System.Security.AccessControl.AuditFlags]::Success,
			[System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents)

		[System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneSuccess)

		Write-Output -InputObject $Rules
	}

	End {
	}
}

Function New-RIDManagerAuditRuleSet {
	<#
		.SYNOPSIS
			Creates the audit rule set for the RID Manager object.

		.DESCRIPTION
			The New-RIDManagerAuditRuleSet cmdlet sets the required auditing for the RID Manager object.

        .EXAMPLE
			New-RIDManagerAuditRuleSet

	        Creates the audit rules.

		.INPUTS
			None

		.OUTPUTS
			System.DirectoryServices.ActiveDirectoryAuditRule[]

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATED: 2/27/2016
	#>

	[CmdletBinding()]
	Param()

	Begin {	
	}
    
	Process
	{
		$Everyone = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::WorldSid, $null)

		$EveryoneFail = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
			[System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
			[System.Security.AccessControl.AuditFlags]::Failure, 
			[System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

		$EveryoneSuccess = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($Everyone,
			@([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
			[System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight),
			[System.Security.AccessControl.AuditFlags]::Success,
			[System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)

		[System.DirectoryServices.ActiveDirectoryAuditRule[]] $Rules = @($EveryoneFail, $EveryoneSuccess)

		Write-Output -InputObject $Rules
	}

	End{	
	}
}

Function Get-ForestDomains {
	<#
		.SYNOPSIS
			Gets all of the domains in the current Active Directory Forest.

		.DESCRIPTION
			The Get-ForestDomains cmdlet gets all of the domains in the current Active Directory Forest.

        .EXAMPLE
			Get-ForestDomains

	        Gets all of the domains in the Forest of the logged on user.

		.INPUTS
			None

		.OUTPUTS
			System.String[]

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATED: 2/27/2016
	#>

	[CmdletBinding()]
    Param
    ()

    Begin {
	}

    Process
    {
		try
        {
            $Forest = Get-ADForest -Current LocalComputer
            $ForestDN = (Get-ADDomain -Identity ($Forest.RootDomain)).DistinguishedName
			Write-Output -InputObject $Forest.Domains
        }
        catch [System.Exception]
        {
            Write-Warning $_.Exception.Message
			Exit 1
        }
    }

    End {	
	}
}

Function Write-Results {
	<#
		.SYNOPSIS
			Writes the ACL configuration output results.

		.DESCRIPTION
			The Write-Results cmdlet outputs the modified ACL.

		.PARAMETER Path
			The path of the Active Directory object to get the ACL of.

		.PARAMETER Domain
			The domain the object belongs to.

        .EXAMPLE
			Write-Results -Path "dc=contso,sc=com" -Domain "contoso.com"

	        Writes the current ACL of the domain object.

		.INPUTS
			None

		.OUTPUTS
			System.Security.AccessControl.AuthorizationRuleCollection

		.NOTES
			AUTHOR: Michael Haken
			LAST UPDATE: 2/27/2016
	#>

	[CmdletBinding()]
    Param
    (
        [Parameter(Position=0,Mandatory=$true)]
        [string]$Path,

        [Parameter(Position=1,Mandatory=$true)]
        [string]$Domain
    )

	Begin {
	}

	Process {
		$Acl = Get-Acl -Path $Path 
		Write-Host $Domain -ForegroundColor DarkRed -BackgroundColor White
		Write-Host ($Path.Substring($Path.IndexOf(":") + 1)) -ForegroundColor DarkRed -BackgroundColor White
		Write-Output -InputObject $Acl.Access
	}

	End {
	}
}
