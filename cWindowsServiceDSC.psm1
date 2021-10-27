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

<#
    .SYNOPSIS
        Grants the 'Log on as a service' right to the user with the given username.

    .PARAMETER Username
        The username of the user to grant 'Log on as a service' right to
#>
function Grant-LogOnAsServiceRight
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Username
    )

    $logOnAsServiceText = @"
        namespace LogOnAsServiceHelper
        {
            using Microsoft.Win32.SafeHandles;
            using System;
            using System.Runtime.ConstrainedExecution;
            using System.Runtime.InteropServices;
            using System.Security;

            public class NativeMethods
            {
                #region constants
                // from ntlsa.h
                private const int POLICY_LOOKUP_NAMES = 0x00000800;
                private const int POLICY_CREATE_ACCOUNT = 0x00000010;
                private const uint ACCOUNT_ADJUST_SYSTEM_ACCESS = 0x00000008;
                private const uint ACCOUNT_VIEW = 0x00000001;
                private const uint SECURITY_ACCESS_SERVICE_LOGON = 0x00000010;

                // from LsaUtils.h
                private const uint STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034;

                // from lmcons.h
                private const int UNLEN = 256;
                private const int DNLEN = 15;

                // Extra characteres for '\', '@' etc.
                private const int EXTRA_LENGTH = 3;
                #endregion constants

                #region interop structures
                /// <summary>
                /// Used to open a policy, but not containing anything meaqningful
                /// </summary>
                [StructLayout(LayoutKind.Sequential)]
                private struct LSA_OBJECT_ATTRIBUTES
                {
                    public UInt32 Length;
                    public IntPtr RootDirectory;
                    public IntPtr ObjectName;
                    public UInt32 Attributes;
                    public IntPtr SecurityDescriptor;
                    public IntPtr SecurityQualityOfService;

                    public void Initialize()
                    {
                        this.Length = 0;
                        this.RootDirectory = IntPtr.Zero;
                        this.ObjectName = IntPtr.Zero;
                        this.Attributes = 0;
                        this.SecurityDescriptor = IntPtr.Zero;
                        this.SecurityQualityOfService = IntPtr.Zero;
                    }
                }

                /// <summary>
                /// LSA string
                /// </summary>
                [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
                private struct LSA_UNICODE_STRING
                {
                    internal ushort Length;
                    internal ushort MaximumLength;
                    [MarshalAs(UnmanagedType.LPWStr)]
                    internal string Buffer;

                    internal void Set(string src)
                    {
                        this.Buffer = src;
                        this.Length = (ushort)(src.Length * sizeof(char));
                        this.MaximumLength = (ushort)(this.Length + sizeof(char));
                    }
                }

                /// <summary>
                /// Structure used as the last parameter for LSALookupNames
                /// </summary>
                [StructLayout(LayoutKind.Sequential)]
                private struct LSA_TRANSLATED_SID2
                {
                    public uint Use;
                    public IntPtr SID;
                    public int DomainIndex;
                    public uint Flags;
                };
                #endregion interop structures

                #region safe handles
                /// <summary>
                /// Handle for LSA objects including Policy and Account
                /// </summary>
                private class LsaSafeHandle : SafeHandleZeroOrMinusOneIsInvalid
                {
                    [DllImport("advapi32.dll")]
                    private static extern uint LsaClose(IntPtr ObjectHandle);

                    /// <summary>
                    /// Prevents a default instance of the LsaPolicySafeHAndle class from being created.
                    /// </summary>
                    private LsaSafeHandle(): base(true)
                    {
                    }

                    /// <summary>
                    /// Calls NativeMethods.CloseHandle(handle)
                    /// </summary>
                    /// <returns>the return of NativeMethods.CloseHandle(handle)</returns>
                    [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
                    protected override bool ReleaseHandle()
                    {
                        long returnValue = LsaSafeHandle.LsaClose(this.handle);
                        return returnValue != 0;

                    }
                }

                /// <summary>
                /// Handle for IntPtrs returned from Lsa calls that have to be freed with
                /// LsaFreeMemory
                /// </summary>
                private class SafeLsaMemoryHandle : SafeHandleZeroOrMinusOneIsInvalid
                {
                    [DllImport("advapi32")]
                    internal static extern int LsaFreeMemory(IntPtr Buffer);

                    private SafeLsaMemoryHandle() : base(true) { }

                    private SafeLsaMemoryHandle(IntPtr handle)
                        : base(true)
                    {
                        SetHandle(handle);
                    }

                    private static SafeLsaMemoryHandle InvalidHandle
                    {
                        get { return new SafeLsaMemoryHandle(IntPtr.Zero); }
                    }

                    override protected bool ReleaseHandle()
                    {
                        return SafeLsaMemoryHandle.LsaFreeMemory(handle) == 0;
                    }

                    internal IntPtr Memory
                    {
                        get
                        {
                            return this.handle;
                        }
                    }
                }
                #endregion safe handles

                #region interop function declarations
                /// <summary>
                /// Opens LSA Policy
                /// </summary>
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaOpenPolicy(
                    IntPtr SystemName,
                    ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
                    uint DesiredAccess,
                    out LsaSafeHandle PolicyHandle
                );

                /// <summary>
                /// Convert the name into a SID which is used in remaining calls
                /// </summary>
                [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
                private static extern uint LsaLookupNames2(
                    LsaSafeHandle PolicyHandle,
                    uint Flags,
                    uint Count,
                    LSA_UNICODE_STRING[] Names,
                    out SafeLsaMemoryHandle ReferencedDomains,
                    out SafeLsaMemoryHandle Sids
                );

                /// <summary>
                /// Opens the LSA account corresponding to the user's SID
                /// </summary>
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaOpenAccount(
                    LsaSafeHandle PolicyHandle,
                    IntPtr Sid,
                    uint Access,
                    out LsaSafeHandle AccountHandle);

                /// <summary>
                /// Creates an LSA account corresponding to the user's SID
                /// </summary>
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaCreateAccount(
                    LsaSafeHandle PolicyHandle,
                    IntPtr Sid,
                    uint Access,
                    out LsaSafeHandle AccountHandle);

                /// <summary>
                /// Gets the LSA Account access
                /// </summary>
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaGetSystemAccessAccount(
                    LsaSafeHandle AccountHandle,
                    out uint SystemAccess);

                /// <summary>
                /// Sets the LSA Account access
                /// </summary>
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaSetSystemAccessAccount(
                    LsaSafeHandle AccountHandle,
                    uint SystemAccess);
                #endregion interop function declarations

                /// <summary>
                /// Sets the Log On As A Service Policy for <paramref name="userName"/>, if not already set.
                /// </summary>
                /// <param name="userName">the user name we want to allow logging on as a service</param>
                /// <exception cref="ArgumentNullException">If the <paramref name="userName"/> is null or empty.</exception>
                /// <exception cref="InvalidOperationException">In the following cases:
                ///     Failure opening the LSA Policy.
                ///     The <paramref name="userName"/> is too large.
                ///     Failure looking up the user name.
                ///     Failure opening LSA account (other than account not found).
                ///     Failure creating LSA account.
                ///     Failure getting LSA account policy access.
                ///     Failure setting LSA account policy access.
                /// </exception>
                public static void SetLogOnAsServicePolicy(string userName)
                {
                    if (String.IsNullOrEmpty(userName))
                    {
                        throw new ArgumentNullException("userName");
                    }

                    LSA_OBJECT_ATTRIBUTES objectAttributes = new LSA_OBJECT_ATTRIBUTES();
                    objectAttributes.Initialize();

                    // All handles are delcared in advance so they can be closed on finally
                    LsaSafeHandle policyHandle = null;
                    SafeLsaMemoryHandle referencedDomains = null;
                    SafeLsaMemoryHandle sids = null;
                    LsaSafeHandle accountHandle = null;

                    try
                    {
                        uint status = LsaOpenPolicy(
                            IntPtr.Zero,
                            ref objectAttributes,
                            POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT,
                            out policyHandle);

                        if (status != 0)
                        {
                            throw new InvalidOperationException("CannotOpenPolicyErrorMessage");
                        }

                        // Unicode strings have a maximum length of 32KB. We don't want to create
                        // LSA strings with more than that. User lengths are much smaller so this check
                        // ensures userName's length is useful
                        if (userName.Length > UNLEN + DNLEN + EXTRA_LENGTH)
                        {
                            throw new InvalidOperationException("UserNameTooLongErrorMessage");
                        }

                        LSA_UNICODE_STRING lsaUserName = new LSA_UNICODE_STRING();
                        lsaUserName.Set(userName);

                        LSA_UNICODE_STRING[] names = new LSA_UNICODE_STRING[1];
                        names[0].Set(userName);

                        status = LsaLookupNames2(
                            policyHandle,
                            0,
                            1,
                            new LSA_UNICODE_STRING[] { lsaUserName },
                            out referencedDomains,
                            out sids);

                        if (status != 0)
                        {
                            throw new InvalidOperationException("CannotLookupNamesErrorMessage");
                        }

                        LSA_TRANSLATED_SID2 sid = (LSA_TRANSLATED_SID2)Marshal.PtrToStructure(sids.Memory, typeof(LSA_TRANSLATED_SID2));

                        status = LsaOpenAccount(policyHandle,
                                            sid.SID,
                                            ACCOUNT_VIEW | ACCOUNT_ADJUST_SYSTEM_ACCESS,
                                            out accountHandle);

                        uint currentAccess = 0;

                        if (status == 0)
                        {
                            status = LsaGetSystemAccessAccount(accountHandle, out currentAccess);

                            if (status != 0)
                            {
                                throw new InvalidOperationException("CannotGetAccountAccessErrorMessage");
                            }

                        }
                        else if (status == STATUS_OBJECT_NAME_NOT_FOUND)
                        {
                            status = LsaCreateAccount(
                                policyHandle,
                                sid.SID,
                                ACCOUNT_ADJUST_SYSTEM_ACCESS,
                                out accountHandle);

                            if (status != 0)
                            {
                                throw new InvalidOperationException("CannotCreateAccountAccessErrorMessage");
                            }
                        }
                        else
                        {
                            throw new InvalidOperationException("CannotOpenAccountErrorMessage");
                        }

                        if ((currentAccess & SECURITY_ACCESS_SERVICE_LOGON) == 0)
                        {
                            status = LsaSetSystemAccessAccount(
                                accountHandle,
                                currentAccess | SECURITY_ACCESS_SERVICE_LOGON);
                            if (status != 0)
                            {
                                throw new InvalidOperationException("CannotSetAccountAccessErrorMessage");
                            }
                        }
                    }
                    finally
                    {
                        if (policyHandle != null) { policyHandle.Close(); }
                        if (referencedDomains != null) { referencedDomains.Close(); }
                        if (sids != null) { sids.Close(); }
                        if (accountHandle != null) { accountHandle.Close(); }
                    }
                }
            }
        }
"@

    try
    {
        $null = [LogOnAsServiceHelper.NativeMethods]
    }
    catch
    {
      $null = Add-Type $logOnAsServiceText -PassThru  
    }

    if ($Username.StartsWith('.\'))
    {
        $Username = $Username.Substring(2)
    }

    try 
    {
        [LogOnAsServiceHelper.NativeMethods]::SetLogOnAsServicePolicy($Username)
    }
    catch 
    {
        throw 
    }
}

    <#
    .SYNOPSIS
        Converts the given username to the string version of it that would be expected in a
        service's StartName property.

    .PARAMETER Username
        The username to convert.
    #>
    function ConvertTo-StartName
    {
        [OutputType([System.String])]
        [CmdletBinding()]
        param
        (
            [Parameter(Mandatory = $true)]
            [ValidateNotNullOrEmpty()]
            [System.String]
            $Username
        )
    
        $startName = $Username
    
        if ($Username -ieq 'NetworkService' -or $Username -ieq 'LocalService' -or $Username -ieq 'LocalSystem')
        {
            $startName = "NT Authority\$Username"
            return $startName
        }

        if (-not $Username.Contains('\') -and -not $Username.Contains('@'))
        {
            $startName = ".\$Username"
            return $startName
        }
        
        if ($Username.StartsWith("$env:computerName\"))
        {
            $startName = $Username.Replace($env:computerName, '.')
            return $startName
        }
    
        return $startName
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

    [DscProperty(NotConfigurable)]
    [String]$ServiceUser

    [DscProperty(Mandatory = $true)]
    [Ensure]$Ensure

    [DscProperty(Mandatory = $false)]
    [RecoveryType]$RecoveryType = [RecoveryType]::Restart

    [DscProperty(Mandatory = $false)]
    [StartupType]$StartupType = [StartupType]::Automatic

    [DscProperty(Mandatory = $false)]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = (New-Object -TypeName pscredential -ArgumentList 'NT AUTHORITY\SYSTEM', $(ConvertTo-SecureString -AsPlainText -Force -string 'whatever'))

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

            $this.ServiceUser = (Get-WmiObject -Class Win32_Service -Filter "name='$($this.ServiceName)'").Startname
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
        Write-Verbose "Desired State is: $($this.ServiceName) ServiceUser $($this.ServiceUser)"

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

        if ($ServiceInfo.ServiceUser -ne $this.Credential.UserName)
        {
            $serviceCimInstance = Get-CimInstance -ClassName 'Win32_Service' -Filter "Name='$($this.ServiceName)'"
            $changeServiceArguments = @{}
            Write-Verbose "Setting Service $($this.Servicename) User from $($ServiceInfo.ServiceUser) to $($this.Credential.UserName)"
            
            $startName = ConvertTo-StartName -Username $this.Credential.UserName
            Write-Verbose "The service startName is $startName"
            Grant-LogOnAsServiceRight -Username $startName
            $changeServiceArguments['StartName'] = $startName
            If($this.Credential.GetNetworkCredential().Password)
            {
                $changeServiceArguments['StartPassword'] = $this.Credential.GetNetworkCredential().Password
            }
            $changeServiceResult = Invoke-CimMethod -InputObject $ServiceCimInstance -MethodName 'Change' -Arguments $changeServiceArguments
            if ($changeServiceResult.ReturnValue -ne 0)
            {
                throw "Service $($this.Servicename) credential change failed with error code $($changeServiceResult.ReturnValue)"
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


        if ($ServiceInfo.ServiceUser -ne $this.Credential.UserName)
        {
            Write-Verbose "$($this.ServiceName) User expects to be $($this.Credential.UserName), But $($ServiceInfo.ServiceUser)"
            return $false
        }

        Write-Verbose "$($this.ServiceName) RecoveryType: $($this.ServiceCurrentRecoveryType):$($this.ServiceCurrentRecoveryType.count), StartupType: $($this.ServiceCurrentStartupType)"
        return $true
    }
}
