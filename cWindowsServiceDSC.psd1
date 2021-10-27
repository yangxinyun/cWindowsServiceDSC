@{
    RootModule           = 'cWindowsServiceDSC.psm1'
    DscResourcesToExport = @('WindowsServiceDSC')

    # Version number of this module.
    ModuleVersion        = '0.0.2'

    # ID used to uniquely identify this module
    GUID                 = 'e74c78aa-62ec-41ab-992b-9928d97dd530'

    # Author of this module
    Author               = 'Yang Xinyun'

    # Company or vendor of this module
    CompanyName          = 'Yang Xinyun'

    # Copyright statement for this module
    Copyright            = '(c) 2021 Yang Xinyun. All rights reserved.'

    # Description of the functionality provided by this module
    Description          = 'Powershell DSC Resource to configure Windows service startup type and Recovery.'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion    = '5.1'

    PrivateData          = @{

        PSData = @{
    
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags                     = @('DSC', 'DSCResource', 'DesiredStateConfiguration', 'WindowsService')
    
            # A URL to the license for this module.
            # LicenseUri = ''
    
            # A URL to the main website for this project.
            ProjectUri               = 'https://github.com/yangxinyun/cWindowsServiceDSC'
    
            # A URL to an icon representing this module.
            IconUri                  = 'https://toppng.com/uploads/preview/ear-icon-free-windows-service-ico-11563265466nw6vqap7gv.png'
    
            # ReleaseNotes of this module
            # ReleaseNotes = ''
    
            # Prerelease string of this module
            # Prerelease = ''
    
            # Flag to indicate whether the module requires explicit user acceptance for install/update/save
            RequireLicenseAcceptance = $false
    
            # External dependent modules of this module
            # ExternalModuleDependencies = @()
    
        } # End of PSData hashtable
    
    }

}
