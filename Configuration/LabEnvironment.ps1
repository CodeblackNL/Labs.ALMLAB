Configuration CommonServer {
    param (
        [string]$ShareHostName,
        [PSCredential]$ShareCredential
    )

    Import-DscResource –ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'xNetworking'
    Import-DscResource -ModuleName 'xRemoteDesktopAdmin'
    Import-DscResource -ModuleName 'CredentialManagement'

    # Administrator password never expires
    User Administrator {
        Ensure                 = 'Present'
        UserName               = 'Administrator'
        PasswordChangeRequired = $false
        PasswordNeverExpires   = $true
    }

    foreach ($networkAdapter in $Node.NetworkAdapters) {
        $network = $networkAdapter.Network
        if ($networkAdapter.StaticIPAddress) {
            xDhcpClient "DisableDHCP_$($network.Name)" {
                InterfaceAlias     = $network.Name
                AddressFamily      = $network.AddressFamily
                State              = 'Disabled'
            }

            xIPAddress "Network_$($networkAdapter.Network.Name)" {
                InterfaceAlias     = $network.Name
                AddressFamily      = $network.AddressFamily
                IPAddress          = $networkAdapter.StaticIPAddress
                SubnetMask         = $network.PrefixLength
                DependsOn          = "[xDhcpClient]DisableDHCP_$($network.Name)"
            }

            if ($network.DnsServer -and $network.DnsServer.IPAddress) {
                xDnsServerAddress "DnsServerAddress_$($networkAdapter.Network.Name)" {
                    InterfaceAlias = $network.Name
                    AddressFamily  = $network.AddressFamily
                    Address        = $network.DnsServer.IPAddress
                    DependsOn      = "[xIPAddress]Network_$($network.Name)"
                }
            }
        }
        else {
            xDhcpClient "EnableDHCP_$($network.Name)" {
                InterfaceAlias     = $network.Name
                AddressFamily      = $network.AddressFamily
                State              = 'Enabled'
            }
        }
    }

    xRemoteDesktopAdmin RemoteDesktopSettings {
        Ensure                 = 'Present' 
        UserAuthentication     = 'Secure'
    }
    xFirewall AllowRDP {
        Ensure                 = 'Present'
        Name                   = 'RemoteDesktop-UserMode-In-TCP'
        Enabled                = 'True'
    }

    Registry DoNotOpenServerManagerAtLogon {
        Ensure                 = 'Present'
        Key                    = 'HKLM:\SOFTWARE\Microsoft\ServerManager'
        ValueName              = 'DoNotOpenServerManagerAtLogon'
        ValueType              = 'Dword'
        ValueData              = 0x1
    }

	if ($ShareHostName -and $ShareCredential) {
        bManagedCredential ShareCredential {
            TargetName = $ShareHostName
            Ensure = 'Present'
            Credential = $ShareCredential
            CredentialType = 'DomainPassword'
            PersistanceScope ='LocalMachine'
        }
    }
}

Configuration DomainController {
    param (
        $Domain,
        [PSCredential]$DomainCredential
    )

    Import-DscResource –ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'xComputerManagement'
    Import-DscResource -ModuleName 'xActiveDirectory'
    Import-DscResource -ModuleName 'xDnsServer'

    xComputer ComputerName {
        Name                           = $Node.Name
    }

    WindowsFeature ADDS {
        Name                           = 'AD-Domain-Services'
        DependsOn                      = '[xComputer]ComputerName'
    }
    WindowsFeature ADDSMgmtTools {
        Name                           = 'RSAT-ADDS-Tools'
        DependsOn                      = '[WindowsFeature]ADDS'
    }

    xADDomain ADDSForest { 
        DomainName                     = $Domain.Name
        DomainAdministratorCredential  = $DomainCredential
        SafemodeAdministratorPassword  = $DomainCredential
        DependsOn                      = "[WindowsFeature]ADDSMgmtTools"
    }

    # TODO: domain-users
    # TODO: DNS-aliases
}

Configuration MemberServer {
    param (
        $Domain,
        [PSCredential]$DomainCredential
    )

    Import-DscResource –ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'xActiveDirectory'
    Import-DscResource -ModuleName 'xComputerManagement'

    xWaitForADDomain WaitForDomain
    {
        DomainName             = $Domain.Name
        DomainUserCredential   = $DomainCredential
        RetryIntervalSec       = 30
        RetryCount             = 480
    }
    xComputer ComputerNameAndDomain {
        Name                   = $Node.Name
        DomainName             = $Domain.Name
        Credential             = $DomainCredential
        DependsOn              = '[xWaitForADDomain]WaitForDomain'
    }
}

Configuration DhcpServer {
    param (
        $DhcpServer,
        $DnsServerIPAddress
    )

    Import-DscResource –ModuleName 'xDhcpServer'
    Import-DscResource –ModuleName 'bDhcpServer'

    WindowsFeature Dhcp {
        Name               = 'DHCP'
    }
    bDhcpServerConfigurationCompletion DhcpCompletion {
        Ensure             = 'Present'
        DependsOn          = '[WindowsFeature]Dhcp'
    }
    WindowsFeature DhcpMgmtTools {
        Name               = 'RSAT-DHCP'
        DependsOn          = '[WindowsFeature]Dhcp'
    }

    xDhcpServerAuthorization DhcpServerAuthorization {
        Ensure             = 'Present'
    }

    # NOTE: Binding not needed (?), binds to correct interface automatically
    #       Set-DhcpServerv4Binding -InterfaceAlias 'Internal' -BindingState $true

    xDhcpServerScope DhcpScope {
        Ensure             = 'Present'
        Name               = $DhcpServer.ScopeName
        IPStartRange       = $DhcpServer.StartRange
        IPEndRange         = $DhcpServer.EndRange
        SubnetMask         = $DhcpServer.SubnetMask
        LeaseDuration      = $DhcpServer.LeaseDurationDays
        State              = 'Active'
        DependsOn          = '[bDhcpServerConfigurationCompletion]DhcpCompletion'
    }
    xDhcpServerOption DhcpOptions {
        Ensure             = 'Present'
        ScopeID            = $DhcpServer.ScopeId
        DnsServerIPAddress = $DnsServerIPAddress
        Router             = $DhcpServer.DefaultGateway
        DependsOn          = '[xDhcpServerScope]DhcpScope'
    }

    # TODO: DHCP-reservations
}

Configuration ManagementServer {
    param (
        [string]$SharePath,
        [PSCredential]$ShareCredential
    )

    Import-DscResource –ModuleName 'PSDesiredStateConfiguration'

    WindowsFeature ADDSMgmtTools {
        Name                   = 'RSAT-ADDS-Tools'
    }
    WindowsFeature DnsMgmtTools {
        Name                   = 'RSAT-DNS-Server'
    }
    WindowsFeature DhcpMgmtTools {
        Name                   = 'RSAT-DHCP'
    }

    WindowsFeature NETFrameworkCore {
        Ensure = "Present"
        Name = "NET-Framework-Core"
        Source = Join-Path -Path $SharePath -ChildPath 'iso\w2016\sources\sxs'
    }
    Package SqlServer2016ManagementStudio {
        Name        = 'SQL Server 2016 Management Studio'
        Ensure      = 'Present'
        ProductId   = '9C9F6116-632F-4626-88B1-3E486776C991'
        Arguments   = '/install /quiet /norestart'
        LogPath     = 'C:\Setup\SSMS-Setup-ENU.txt'
        Path        = Join-Path -Path $SharePath -ChildPath 'install\SSMS-Setup-ENU.exe'
        Credential  = $ShareCredential
    } 
}

Configuration VisualStudio {
    param (
        [string]$SharePath,
        [PSCredential]$ShareCredential
    )

    Import-DscResource -ModuleName 'bVisualStudio'

    $adminDeploymentFilePath = 'C:\Setup\vs\VS2015AdminDeployment.xml'
    File RegistrationKeyFile {
        DestinationPath = $adminDeploymentFilePath
        Type = 'File'
        Ensure = 'Present'
        SourcePath = Join-Path -Path $SharePath -ChildPath 'install\VS2015AdminDeployment.xml'
        Credential = $ShareCredential
    }

    # VS2015 :
    # - https://msdn.microsoft.com/en-us/library/ee225237.aspx
    # - https://msdn.microsoft.com/library/e2h7fzkw.aspx
    # vs_enterprise.exe /layout e:\HyperV\Share\iso\vs2015.3.full /overridefeeduri "http://go.microsoft.com/fwlink/?LinkID=785882&clcid0x409"
    bVisualStudioSetup VisualStudio2015 {
        AdminFilePath = $adminDeploymentFilePath
        Ensure = 'Present'
        SourcePath = "$SharePath\iso\vs2015.3.full"
        SourceCredential = $ShareCredential
    }

    # VS2015 Extensions :
    # - PowerShell
    # - 
}

Configuration SqlServer {
    param (
        [string]$SharePath,
        [PSCredential]$ShareCredential,
        [PSCredential]$DomainCredential,
        [string[]]$Features = @('SQLENGINE'),
        [string]$SqlInstanceName = 'MSSQLSERVER'
    )

    Import-DscResource –ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'xSqlServer'

    WindowsFeature NETFrameworkCore {
        Ensure = "Present"
        Name = "NET-Framework-Core"
        Source = Join-Path -Path $SharePath -ChildPath 'iso\w2016\sources\sxs'
    }

    xSqlServerSetup SqlServer2016 {
        SourcePath             = Join-Path -Path $SharePath -ChildPath 'iso\sql2016_dev'
        SourceFolder           = ''
        SourceCredential       = $ShareCredential

        PID                    = $Node.AllProperties.SqlProductKey
        Features               = [string]::Join(',', $Features)
        SetupCredential        = $DomainCredential

        # SQLENGINE
        InstanceName           = $SqlInstanceName
        SecurityMode           = 'SQL'
        SAPwd                  = $DomainCredential
        InstallSQLDataDir      = 'D:\Data'
        SQLCollation           = 'Latin1_General_CI_AS'
        SQLSysAdminAccounts    = ($DomainCredential).UserName
        #SQLSvcAccount          = $Node.ServiceAccount
        #AgtSvcAccount          = $Node.ServiceAccount

        # FULLTEXT
        #FTSvcAccount           = "NT Service\MSSQLFDLauncher"

        # AS
        #ASSvcAccountUserName   = "NT AUTHORITY\SYSTEM"      # "NT Service\MSSQLServerOLAPService"
        ASDataDir              = 'D:\Data\OLAP'
        ASSysAdminAccounts     = ($DomainCredential).UserName

        DependsOn              = '[WindowsFeature]NETFrameworkCore'
    }

    xSQLServerNetwork SqlServer2016TcpIp {
        InstanceName           = $SqlInstanceName
        ProtocolName           = 'tcp'
        IsEnabled              = $true
        TCPPort                = 1433
        RestartService          = $true 
        DependsOn              = '[xSqlServerSetup]SqlServer2016'
    }
    
    xSqlServerFirewall SqlServer2016Firewall {
        SourcePath             = Join-Path -Path $SharePath -ChildPath 'iso\sql2016_dev'
        SourceFolder           = ''
        Features               = [string]::Join(',', $Features)
        InstanceName           = $SqlInstanceName
        DependsOn              = '[xSQLServerNetwork]SqlServer2016TcpIp'
    }
}

Configuration TfsServer {
    param (
        [string]$SharePath,
        [PSCredential]$ShareCredential,
        [PSCredential]$DomainCredential
    )

    Import-DscResource –ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'xNetworking'
    Import-DscResource -ModuleName 'xSqlServer'
    Import-DscResource -ModuleName 'bTfsServer'

    SqlServer SqlServer2016 {
        SharePath = $SharePath
        ShareCredential = $ShareCredential
        DomainCredential = $DomainCredential
        Features = @('SQLENGINE','FULLTEXT','RS','AS')
    }

    Package Hotfix_KB3138367 {
        Name        = 'Microsoft Visual C++ 2013 Redistributable (x64) - 12.0.40649'
        Ensure      = 'Present'
        ProductId   = '5d0723d3-cff7-4e07-8d0b-ada737deb5e6'
        Arguments   = '/install /quiet /norestart /log C:\Setup\log\KB3138367.txt'
        LogPath     = 'C:\Setup\log\KB3138367_log.txt'
        Path        = Join-Path -Path $SharePath -ChildPath 'install\vcredist_x64.exe'
        Credential  = $ShareCredential
    }

    # TODO: use sa-tfs as service-account
    # NOTE: installing a TFS Server 2013 with a domain-service-account through DSC resulted in a crashing AppPool
    bTfsServerSetup TfsServer15 {
        SourcePath                 = Join-Path -Path $SharePath -ChildPath 'iso\tfs15_rc2'
        SourceCredential           = $ShareCredential
        LogPath                    = "C:\Setup\log"
        SendFeedback               = $true
        Name                       = $Node.NodeName
        SqlServerInstance          = $Node.NodeName
        #TeamProjectCollectionName  = 'DefaultCollection'
        TfsServiceAccountUserName  = 'NT AUTHORITY\Network Service'
        #ReportReaderAccount        = $Node.TfsReportsCredential
        TfsAdminCredential         = $DomainCredential
        FileCacheDirectory         = 'D:\Cache'
        Ensure                     = 'Present'
        DependsOn                  = '[SqlServer]SqlServer2016'
    }

	xFirewall TfsServerFirewall {
        Ensure             = 'Present'
        Name               = 'Team Foundation Server:8080'
        Direction          = 'InBound'
        LocalPort          = '8080'
        Protocol           = 'TCP'
        Profile            = 'Any'
        Action             = 'Allow'
        Enabled            = 'True'
	}
}

Configuration TfsAgent {
    Import-DscResource -ModuleName 'bTfsServer'
    Import-DscResource -ModuleName 'xCredSSP'

    if ($Node.AllProperties.AgentName -and $Node.AllProperties.AgentUserName -and $Node.AllProperties.AgentPassword) {
        xCredSSP CredSSPServer {
            Role = 'Server'
            Ensure = 'Present'
        }

        xCredSSP CredSSPClient {
            Role = 'Client'
            Ensure = 'Present'
            DelegateComputers = '*'
        }

        $securePassword = (ConvertTo-SecureString -String $Node.AllProperties.AgentPassword -AsPlainText -Force)
        $serverCredential = New-Object -TypeName PSCredential -ArgumentList $Node.AllProperties.AgentUserName,$securePassword

        $agentName = $Node.AllProperties.AgentName
        bTfsAgentSetup TfsAgent {
            AgentName = $agentName
            Ensure = 'Present'
            ServerUrl = $Node.AllProperties.TfsServerUrl
            AgentCredential = $serverCredential
            PoolName = 'default'
            AgentFolder = "D:\Agent_$($agentName)"
            RunAsWindowsService = $true
        }
    }
}

Configuration SonarServer {
    param (
        [string]$SharePath,
        [PSCredential]$ShareCredential,
        [PSCredential]$DomainCredential
    )

    Import-DscResource –ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'xSqlServer'

    SqlServer SqlServer2016 {
        SharePath = $SharePath
        ShareCredential = $ShareCredential
        DomainCredential = $DomainCredential
        Features = @('SQLENGINE')
    }
}

Configuration TargetServer {
    Import-DscResource –ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource –ModuleName 'xNetworking'

    xFirewall FileAndPrinterSharing_FPS-NB_Session-In-TCP {
        Name = 'FPS-NB_Session-In-TCP'
        Enabled = 'True'
    }
    xFirewall FileAndPrinterSharing_FPS-NB_Session-Out-TCP {
        Name = 'FPS-NB_Session-Out-TCP'
        Enabled = 'True'
    }
    xFirewall FileAndPrinterSharing_FPS-SMB-In-TCP {
        Name = 'FPS-SMB-In-TCP'
        Enabled = 'True'
    }
    xFirewall FileAndPrinterSharing_FPS-SMB-Out-TCP {
        Name = 'FPS-SMB-Out-TCP'
        Enabled = 'True'
    }
    xFirewall FileAndPrinterSharing_FPS-NB_Name-In-UDP {
        Name = 'FPS-NB_Name-In-UDP'
        Enabled = 'True'
    }
    xFirewall FileAndPrinterSharing_FPS-NB_Name-Out-UDP {
        Name = 'FPS-NB_Name-Out-UDP'
        Enabled = 'True'
    }
    xFirewall FileAndPrinterSharing_FPS-NB_Datagram-In-UDP {
        Name = 'FPS-NB_Datagram-In-UDP'
        Enabled = 'True'
    }
    xFirewall FileAndPrinterSharing_FPS-NB_Datagram-Out-UDP {
        Name = 'FPS-NB_Datagram-Out-UDP'
        Enabled = 'True'
    }
    xFirewall FileAndPrinterSharing_FPS-SpoolSvc-In-TCP {
        Name = 'FPS-SpoolSvc-In-TCP'
        Enabled = 'True'
    }
    xFirewall FileAndPrinterSharing_FPS-RPCSS-In-TCP {
        Name = 'FPS-RPCSS-In-TCP'
        Enabled = 'True'
    }
    xFirewall FileAndPrinterSharing_FPS-ICMP4-ERQ-In {
        Name = 'FPS-ICMP4-ERQ-In'
        Enabled = 'True'
    }
    xFirewall FileAndPrinterSharing_FPS-ICMP4-ERQ-Out {
        Name = 'FPS-ICMP4-ERQ-Out'
        Enabled = 'True'
    }
    xFirewall FileAndPrinterSharing_FPS-ICMP6-ERQ-In {
        Name = 'FPS-ICMP6-ERQ-In'
        Enabled = 'True'
    }
    xFirewall FileAndPrinterSharing_FPS-ICMP6-ERQ-Out {
        Name = 'FPS-ICMP6-ERQ-Out'
        Enabled = 'True'
    }
    xFirewall FileAndPrinterSharing_FPS-LLMNR-In-UDP {
        Name = 'FPS-LLMNR-In-UDP'
        Enabled = 'True'
    }
    xFirewall FileAndPrinterSharing_FPS-LLMNR-Out-UDP {
        Name = 'FPS-LLMNR-Out-UDP'
        Enabled = 'True'
    }
    Log FileAndPrinterSharingFinished {
        Message = 'File And Printer Sharing Finished'
        DependsOn = '[xFirewall]FileAndPrinterSharing_FPS-NB_Session-In-TCP','[xFirewall]FileAndPrinterSharing_FPS-NB_Session-Out-TCP','[xFirewall]FileAndPrinterSharing_FPS-SMB-In-TCP','[xFirewall]FileAndPrinterSharing_FPS-SMB-Out-TCP','[xFirewall]FileAndPrinterSharing_FPS-NB_Name-In-UDP','[xFirewall]FileAndPrinterSharing_FPS-NB_Name-Out-UDP','[xFirewall]FileAndPrinterSharing_FPS-NB_Datagram-In-UDP','[xFirewall]FileAndPrinterSharing_FPS-NB_Datagram-Out-UDP','[xFirewall]FileAndPrinterSharing_FPS-SpoolSvc-In-TCP','[xFirewall]FileAndPrinterSharing_FPS-RPCSS-In-TCP','[xFirewall]FileAndPrinterSharing_FPS-ICMP4-ERQ-In','[xFirewall]FileAndPrinterSharing_FPS-ICMP4-ERQ-Out','[xFirewall]FileAndPrinterSharing_FPS-ICMP6-ERQ-In','[xFirewall]FileAndPrinterSharing_FPS-ICMP6-ERQ-Out','[xFirewall]FileAndPrinterSharing_FPS-LLMNR-In-UDP','[xFirewall]FileAndPrinterSharing_FPS-LLMNR-Out-UDP'
    }
}

Configuration LabEnvironment {
    Import-DscResource –ModuleName 'PSDesiredStateConfiguration'

    Node $AllNodes.NodeName {

        <# The following initialization is done in the setup-complete script
            + Initialize PowerShell environment (ExecutionPolicy:Unrestricted)
            + Enable PS-Remoting
            + Enable CredSSP
            + Format Extra-Disk (only if present and not yet formatted)
            + Configure DSC for Pull
        #>

        $domainNetwork = $Node.NetworkAdapters.Network |? { $_.Domain } | Select -First 1
        $domain = $domainNetwork.Domain
        $domainCredential = New-Object -TypeName PSCredential -ArgumentList "$($domain.Name)\Administrator",$domain.AdministratorPassword

        $sharePath = "\\$($Node.Environment.Host.Name)\$($Node.Environment.Host.Share.Name)"
        $shareCredential = New-Object -TypeName PSCredential -ArgumentList "$($Node.Environment.Host.Name)\$($Node.Environment.Host.Share.UserName)",$Node.Environment.Host.Share.Password

        CommonServer CommonServer {
            ShareHostName = $Node.Environment.Host.Name
            ShareCredential = $shareCredential
        }

        if ($Node.Role -contains ('DomainController')) {
            DomainController DomainController {
                Domain = $domain
                DomainCredential = $domainCredential
                DependsOn = '[CommonServer]CommonServer'
            }

            $dependsOn = @('[DomainController]DomainController')
            foreach ($networkAdapter in $Node.NetworkAdapters) {
                $network = $networkAdapter.Network
                if ($networkAdapter.StaticIPAddress -and $network.DhcpServer -and $networkAdapter.StaticIPAddress -eq $network.DhcpServer.IPAddress) {
                    $resourceName = "DhcpServer_$($network.Name)"
                    $dependsOn += "[DhcpServer]$resourceName"
                    DhcpServer $resourceName {
                        DhcpServer = $network.DhcpServer
                        DnsServerIPAddress = $network.DnsServer.IPAddress
                        DependsOn = '[DomainController]DomainController'
                    }
                }
            }

            Log Log_ServerBaseDone {
                Message = "Base configuration of '$($Node.Name)' finished"
                DependsOn = $dependsOn
            }
        }
        else {
            MemberServer MemberServer {
                Domain = $domain
                DomainCredential = $domainCredential
                DependsOn = '[CommonServer]CommonServer'
            }

            Log Log_ServerBaseDone {
                Message = "Base configuration of '$($Node.Name)' finished"
                DependsOn = '[MemberServer]MemberServer'
            }
        }

        $dependsOn = '[Log]Log_ServerBaseDone'
        foreach ($role in $Node.Role) {
            switch ($role) {
                'ManagementServer' {
                    ManagementServer ManagementServer {
                        SharePath = $sharePath
                        ShareCredential = $shareCredential
                        DependsOn = $dependsOn
                    }
                    $dependsOn = '[ManagementServer]ManagementServer'
                }
                'TfsServer' {
                    TfsServer TfsServer {
                        SharePath = $sharePath
                        ShareCredential = $shareCredential
                        DomainCredential = $domainCredential
                        DependsOn = $dependsOn
                    }
                    $dependsOn = '[TfsServer]TfsServer'
                }
                'SonarServer' {
                    SonarServer SonarServer {
                        SharePath = $sharePath
                        ShareCredential = $shareCredential
                        DomainCredential = $domainCredential
                        DependsOn = $dependsOn
                    }
                    $dependsOn = '[SonarServer]SonarServer'
                }
                'SqlServer' {
                    SqlServer SqlServer {
                        SharePath = $sharePath
                        ShareCredential = $shareCredential
                        DomainCredential = $domainCredential
                        DependsOn = $dependsOn
                    }
                    $dependsOn = '[SqlServer]SqlServer'
                }
                'VisualStudio' {
                    VisualStudio VisualStudio {
                        SharePath = $sharePath
                        DependsOn = $dependsOn
                    }
                    $dependsOn = '[VisualStudio]VisualStudio'
                }
                'TfsAgent' {
                    TfsAgent TfsAgent {
                        DependsOn = $dependsOn
                    }
                }
                'TargetServer' {
                    TargetServer TargetServer {
                        DependsOn = $dependsOn
                    }
                    $dependsOn = '[TargetServer]TargetServer'
                }
            }
        }
    }
}
