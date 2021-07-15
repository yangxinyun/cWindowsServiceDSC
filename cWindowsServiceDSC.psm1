enum Ensure
{ 
    Absent
    Present
}

enum StartupType
{ 
    Automatic
    AutomaticDelayed
    Disabled
    Manual
}

enum RecoveryType
{
    Restart
    Reboot
}

function Set-CurrentRecoveryType
{
    param($original, [WindowsServiceDSC]$strongTypedOutput)

    switch -Wildcard ($original)
    {
        "*RESTART*"
        {
            $strongTypedOutput.ServiceCurrentRecoveryType += 'Restart'
            break
        }
        "*REBOOT*"
        {
            $strongTypedOutput.ServiceCurrentRecoveryType += 'Reboot'
            break
        }
    }
}

[DscResource()]
class WindowsServiceDSC
{
    [DscProperty(Key)]
    [String]$ServiceName

    [DscProperty(NotConfigurable)]
    [Ensure]$ServiceExists

    [DscProperty(NotConfigurable)]
    [StartupType]$ServiceCurrentStartupType

    [DscProperty(NotConfigurable)]
    [RecoveryType[]]$ServiceCurrentRecoveryType

    [DscProperty(Mandatory = $true)]
    [Ensure]$Ensure

    [DscProperty(Mandatory = $false)]
    [RecoveryType]$RecoveryType = [RecoveryType]::Restart

    [DscProperty(Mandatory = $false)]
    [StartupType]$StartupType = [StartupType]::Automatic

    # Gets the resource's current state.
    [WindowsServiceDSC] Get()
    {
        try
        {
            Get-Service $this.ServiceName -ErrorAction 'stop'
            $this.ServiceExists = 'Present'

            $servieConfig = (sc.exe qc "$($this.ServiceName)")[4].trim()
            switch ($servieConfig)
            {
                "START_TYPE         : 2   AUTO_START"
                {
                    $this.ServiceCurrentStartupType = 'Automatic'
                }
                "START_TYPE         : 2   AUTO_START  (DELAYED)"
                {
                    $this.ServiceCurrentStartupType = 'AutomaticDelayed'
                }
                "START_TYPE         : 3   DEMAND_START"
                {
                    $this.ServiceCurrentStartupType = 'Manual'
                }
                "START_TYPE         : 4   DISABLED"
                {
                    $this.ServiceCurrentStartupType = 'Disabled'
                }
            }

            $serviceRecoveryConfig = (sc.exe qfailure "$($this.ServiceName)").trim()
            #First Failure Recovery
            Set-CurrentRecoveryType $serviceRecoveryConfig[6] ([ref]$this)

            #Second Failure Recovery
            Set-CurrentRecoveryType $serviceRecoveryConfig[7] ([ref]$this)
            
            #Third Failure Recovery
            Set-CurrentRecoveryType $serviceRecoveryConfig[8] ([ref]$this)
        }
        catch #[Microsoft.PowerShell.Commands.ServiceCommandException] Cannot find this exception type
        {
            $this.ServiceExists = 'Absent'
        }
        return $this
    }
    
    # Sets the desired state of the resource.
    [void] Set()
    {
        Write-Verbose "Desired State is: $($this.ServiceName) $($this.Ensure)"
        Write-Verbose "Desired State is: $($this.ServiceName) StartupType $($this.StartupType))"
        Write-Verbose "Desired State is: $($this.ServiceName) RecoveryType $($this.RecoveryType)"

        $ServiceInfo = $this.Get()
        if ($ServiceInfo.ServiceCurrentStartupType -ne $this.StartupType)
        {
            Write-Verbose "Setting $($this.ServiceName) StartupType to  $($this.StartupType)"
            
            switch ($this.StartupType)
            {
                'Automatic'
                {
                    sc.exe config ($this.ServiceName) start= auto | Write-Verbose
                    break
                }
                'AutomaticDelayed'
                {
                    sc.exe config ($this.ServiceName) start= delayed-auto | Write-Verbose
                    break
                }
                'Disabled'
                {
                    sc.exe config ($this.ServiceName) start= disabled | Write-Verbose
                    break
                }
                'Manual'
                {
                    sc.exe config ($this.ServiceName) start= demand | Write-Verbose
                    break
                }
            }
        }

        if ($ServiceInfo.ServiceCurrentRecoveryType.Where{ $_ -notin $this.RecoveryType } -or $ServiceInfo.ServiceCurrentRecoveryType.Where{ ![string]::IsNullOrWhiteSpace($_) }.count -ne 3)
        {
            Write-Verbose "Setting $($this.ServiceName) RecoveryType to $($this.RecoveryType)"
            
            switch ($this.RecoveryType)
            {   
                'Restart'
                {
                    sc.exe failure ($this.ServiceName) reset= 3600 actions= restart/60000/restart/60000/restart/60000 | Write-Verbose
                    break
                }
                'REBOOT'
                {
                    sc.exe failure ($this.ServiceName) reset= 3600 actions= reboot/60000/reboot/60000/reboot/60000 | Write-Verbose
                    break
                }
            }
        }
    }
    
    # Tests if the resource is in the desired state.
    [bool] Test()
    {
        $ServiceInfo = $this.Get()
        if ($ServiceInfo.ServiceExists -ne $this.Ensure)
        {
            Write-Verbose "$($this.ServiceName) expects to be $($this.Ensure), But $($ServiceInfo.ServiceExists)"
            return $false
        }

        if ($ServiceInfo.ServiceCurrentStartupType -ne $this.StartupType)
        {
            Write-Verbose "$($this.ServiceName) StartupType expects to be $($this.StartupType), But $($ServiceInfo.ServiceCurrentStartupType)"

            return $false
        }

        if ($ServiceInfo.ServiceCurrentRecoveryType.Where{ $_ -notin $this.RecoveryType } -or $ServiceInfo.ServiceCurrentRecoveryType.Where{ ![string]::IsNullOrWhiteSpace($_) }.count -ne 3)
        {
            Write-Verbose "$($this.ServiceName) RecoveryType expects to be $($this.RecoveryType), But $($ServiceInfo.ServiceCurrentRecoveryType)"

            return $false
        }

        Write-Verbose "$($this.ServiceName) RecoveryType: $($this.ServiceCurrentRecoveryType):$($this.ServiceCurrentRecoveryType.count), StartupType: $($this.ServiceCurrentStartupType)"
        return $true
    }
}