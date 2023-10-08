[CmdletBinding()]
param (
    [switch]$Version,
    [switch]$Help,
    [switch]$CheckForUpdate,
    [switch]$DisableCleanup,
    [switch]$DebugMode,
    [switch]$Force
)

# Version
$CurrentVersion = '3.0.1'
$RepoOwner = 'asheroto'
$RepoName = 'winget-install'
$PowerShellGalleryName = 'winget-install'

# Versions
$ProgressPreference = 'SilentlyContinue' # Suppress progress bar (makes downloading super fast)
$ConfirmPreference = 'None' # Suppress confirmation prompts

# Display version if -Version is specified
if ($Version.IsPresent) {
    $CurrentVersion
    exit 0
}

# Display full help if -Help is specified
if ($Help) {
    Get-Help -Name $MyInvocation.MyCommand.Source -Full
    exit 0
}

# Display $PSVersionTable and Get-Host if -Verbose is specified
if ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters['Verbose']) {
    $PSVersionTable
    Get-Host
}

function Get-TempFolder {
    return [System.IO.Path]::GetTempPath()
}

function Get-OSInfo {
    [CmdletBinding()]
    param ()

    try {
        # Get registry values
        $registryValues = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        $releaseIdValue = $registryValues.ReleaseId
        $displayVersionValue = $registryValues.DisplayVersion
        $nameValue = $registryValues.ProductName
        $editionIdValue = $registryValues.EditionId

        # Strip out "Server" from the $editionIdValue if it exists
        $editionIdValue = $editionIdValue -replace "Server", ""

        # Get OS details using Get-CimInstance because the registry key for Name is not always correct with Windows 11
        $osDetails = Get-CimInstance -ClassName Win32_OperatingSystem
        $nameValue = $osDetails.Caption

        # Get architecture details of the OS (not the processor)
        # Get only the numbers
        $architecture = ($osDetails.OSArchitecture -replace "[^\d]").Trim()

        # If 32-bit or 64-bit replace with x32 and x64
        if ($architecture -eq "32") {
            $architecture = "x32"
        } elseif ($architecture -eq "64") {
            $architecture = "x64"
        }

        # Get OS version details (as version object)
        $versionValue = [System.Environment]::OSVersion.Version

        # Determine product type
        # Reference: https://learn.microsoft.com/en-us/dotnet/api/microsoft.powershell.commands.producttype?view=powershellsdk-1.1.0
        if ($osDetails.ProductType -eq 1) {
            $typeValue = "Workstation"
        } elseif ($osDetails.ProductType -eq 2 -or $osDetails.ProductType -eq 3) {
            $typeValue = "Server"
        } else {
            $typeValue = "Bilinmiyor"
        }

        # Extract numerical value from Name
        $numericVersion = ($nameValue -replace "[^\d]").Trim()

        # Create and return custom object with the required properties
        $result = [PSCustomObject]@{
            ReleaseId      = $releaseIdValue
            DisplayVersion = $displayVersionValue
            Name           = $nameValue
            Type           = $typeValue
            NumericVersion = $numericVersion
            EditionId      = $editionIdValue
            Version        = $versionValue
            Architecture   = $architecture
        }

        return $result
    } catch {
        Write-Error "İşletim sistemi sürümü ayrıntıları alınamıyor.Hata: $_"
        exit 1
    }
}

function Get-GitHubRelease {
    [CmdletBinding()]
    param (
        [string]$Owner,
        [string]$Repo
    )
    try {
        $url = "https://api.github.com/repos/$Owner/$Repo/releases/latest"
        $response = Invoke-RestMethod -Uri $url -ErrorAction Stop

        $latestVersion = $response.tag_name
        $publishedAt = $response.published_at

        # Convert UTC time string to local time
        $UtcDateTime = [DateTime]::Parse($publishedAt, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
        $PublishedLocalDateTime = $UtcDateTime.ToLocalTime()

        [PSCustomObject]@{
            LatestVersion     = $latestVersion
            PublishedDateTime = $PublishedLocalDateTime
        }
    } catch {
        Write-Error "Güncellemeler kontrol edilemiyor.Hata: $_"
        exit 1
    }
}

function CheckForUpdate {
    param (
        [string]$RepoOwner,
        [string]$RepoName,
        [version]$CurrentVersion,
        [string]$PowerShellGalleryName
    )

    $Data = Get-GitHubRelease -Owner $RepoOwner -Repo $RepoName

    if ($Data.LatestVersion -gt $CurrentVersion) {
        Write-Output "A new version of $RepoName is available."
        Write-Output "Güncel sürüm: $CurrentVersion."
        Write-Output "En son sürüm: $($Data.LatestVersion)."
        Write-Output "Yayınlanma tarihi: $($Data.PublishedDateTime)."
        Write-Output "En son sürümü şuradan indirebilirsiniz: https://github.com/$RepoOwner/$RepoName/releases"
        if ($PowerShellGalleryName) {
            Write-Output "Or you can run the following command to update:"
            Write-Output "Install-Script $PowerShellGalleryName -Force"
        }
    } else {
        Write-Output "$RepoName is up to date."
        Write-Output "Güncel sürüm: $CurrentVersion."
        Write-Output "En son sürüm: $($Data.LatestVersion)."
        Write-Output "Yayınlanma tarihi: $($Data.PublishedDateTime)."
        Write-Output "Kaynak: https://github.com/$RepoOwner/$RepoName/releases"
    }
    exit 0
}

function Write-Section($text) {
    Write-Output "$text"
}

function Get-WingetDownloadUrl {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Match
    )

    $uri = "https://api.github.com/repos/microsoft/winget-cli/releases"
    Write-Debug "$uri 'den bilgi alınıyor"
    $releases = Invoke-RestMethod -uri $uri -Method Get -ErrorAction stop

    Write-Debug "Son sürümü alınıyor..."
    foreach ($release in $releases) {
        if ($release.name -match "preview") {
            continue
        }
        $data = $release.assets | Where-Object name -Match $Match
        if ($data) {
            return $data.browser_download_url
        }
    }

    Write-Debug "Son sürüme geri dönersek..."
    $latestRelease = $releases | Select-Object -First 1
    $data = $latestRelease.assets | Where-Object name -Match $Match
    return $data.browser_download_url
}

function Get-WingetStatus {
    # Check if winget is installed
    $winget = Get-Command -Name winget -ErrorAction SilentlyContinue

    # If winget is installed, return $true
    if ($null -ne $winget) {
        return $true
    }

    # If winget is not installed, return $false
    return $false
}

function Update-PathEnvironmentVariable {
    param(
        [string]$NewPath
    )

    foreach ($Level in "Machine", "User") {
        # Get the current PATH variable
        $path = [Environment]::GetEnvironmentVariable("PATH", $Level)

        # Check if the new path is already in the PATH variable
        if (!$path.Contains($NewPath)) {
            if ($DebugMode) {
                Write-Output "$Level için PATH değişkenine $NewPath ekleniyor..."
            } else {
                Write-Output "$Level için PATH değişkeni ekleniyor..."
            }

            # Add the new path to the PATH variable
            $path = ($path + ";" + $NewPath).Split(';') | Select-Object -Unique
            $path = $path -join ';'

            # Set the new PATH variable
            [Environment]::SetEnvironmentVariable("PATH", $path, $Level)
        } else {
            if ($DebugMode) {
                Write-Output "$NewPath için PATH değişkeninde zaten mevcut $Level, atlanıyor."
            } else {
                Write-Output "için zaten mevcut olan PATH değişkeni $Level, atlanıyor."
            }
        }
    }
}

function Handle-Error {
    param($ErrorRecord)

    # Store current value
    $OriginalErrorActionPreference = $ErrorActionPreference

    # Set to silently continue
    $ErrorActionPreference = 'SilentlyContinue'

    if ($ErrorRecord.Exception.Message -match '0x80073D06') {
        Write-Warning "Daha yüksek sürüm zaten yüklü."
        Write-Warning "Sorun değil, devam ediliyor...."
    } elseif ($ErrorRecord.Exception.Message -match '0x80073CF0') {
        Write-Warning "Aynı sürüm zaten yüklü."
        Write-Warning "Sorun değil, devam ediliyor...."
    } elseif ($ErrorRecord.Exception.Message -match '0x80073D02') {
        # Stop execution and return the ErrorRecord so that the calling try/catch block throws the error
        Write-Warning "Değiştirilen kaynaklar kullanımda. Windows Terminal / PowerShell / Komut İstemi'ni kapatmayı ve tekrar denemeyi deneyin."
        Write-Warning "Sorun devam ederse, bilgisayarınızı yeniden başlatın."
        return $ErrorRecord
    } elseif ($ErrorRecord.Exception.Message -match 'Uzak sunucuya bağlanılamıyor') {
        Write-Warning "Gerekli dosyaları indirmek için İnternet'e bağlanılamıyor."
        Write-Warning "Komut dosyasını tekrar çalıştırmayı deneyin ve internete bağlı olduğunuzdan emin olun."
        Write-Warning "Bazen nuget.org sunucusu kapalı olabilir, bu nedenle daha sonra tekrar denemeniz gerekebilir."
        return $ErrorRecord
    } elseif ($ErrorRecord.Exception.Message -match "Uzaktaki ad çözümlenemedi") {
        Write-Warning "Gerekli dosyaları indirmek için İnternet'e bağlanılamıyor."
        Write-Warning "Komut dosyasını tekrar çalıştırmayı deneyin ve internete bağlı olduğunuzdan emin olun."
        Write-Warning "Bilgisayarınızda DNS'in doğru çalıştığından emin olun."
    } else {
        # For other errors, we should stop the execution and return the ErrorRecord so that the calling try/catch block throws the error
        return $ErrorRecord
    }

    # Reset to original value
    $ErrorActionPreference = $OriginalErrorActionPreference
}

function Cleanup {
    param (
        [string]$Path,
        [switch]$Recurse
    )

    try {
        if (Test-Path -Path $Path) {
            if ($Recurse -and (Get-Item -Path $Path) -is [System.IO.DirectoryInfo]) {
                Get-ChildItem -Path $Path -Recurse | Remove-Item -Force -Recurse
                Remove-Item -Path $Path -Force -Recurse
            } else {
                Remove-Item -Path $Path -Force
            }
        }
        if ($DebugMode) {
            Write-Output "Silindi: $Path"
        }
    } catch {
        # Errors are ignored
    }
}

function Install-Prerequisite {
    
    param (
        [string]$Name,
        [string]$Url,
        [string]$AlternateUrl,
        [string]$ContentType,
        [string]$Body,
        [string]$NupkgVersion,
        [string]$AppxFileVersion
    )

    $osVersion = Get-OSInfo
    $arch = $osVersion.Architecture

    Write-Section "${arch} ${Name} İndiriliyor & kuruluyor..."

    $ThrowReason = @{
        Message = ""
        Code    = 0
    }
    try {
        # ============================================================================ #
        # Windows 10 / Server 2022 detection
        # ============================================================================ #

        # Function to extract domain from URL
        function Get-DomainFromUrl($url) {
            $uri = [System.Uri]$url
            $domain = $uri.Host -replace "^www\."
            return $domain
        }

        # If Server 2022 or Windows 10, force non-store version of VCLibs (return true)
        $messageTemplate = "{OS} algılandı. {NAME}'in {DOMAIN} sürümü kullanılıyor."

        # Determine the OS-specific information
        $osType = $osVersion.Type
        $osNumericVersion = $osVersion.NumericVersion

        if (($osType -eq "Server" -and $osNumericVersion -eq 2022) -or ($osType -eq "Workstation" -and $osNumericVersion -eq 10)) {
            if ($osType -eq "Server") {
                $osName = "Server 2022"
            } else {
                $osName = "Windows 10"
            }
            $domain = Get-DomainFromUrl $AlternateUrl
            $ThrowReason.Message = ($messageTemplate -replace "{OS}", $osName) -replace "{NAME}", $Name -replace "{DOMAIN}", $domain
            $ThrowReason.Code = 1
            throw
        }

        # ============================================================================ #
        # Primary method
        # ============================================================================ #

        $url = Invoke-WebRequest -Uri $Url -Method "POST" -ContentType $ContentType -Body $Body -UseBasicParsing | ForEach-Object Links | Where-Object outerHTML -match "$Name.+_${arch}__8wekyb3d8bbwe.appx" | ForEach-Object href

        # If the URL is empty, try the alternate method
        if ($url -eq "") {
            $ThrowReason.Message = "URL is empty"
            $ThrowReason.Code = 2
            throw
        }

        if ($DebugMode) {
            Write-Output "URL: ${url}"
        }
        Write-Output "${arch} ${Name} Kuruluyor..."
        Add-AppxPackage $url -ErrorAction Stop
        Write-Output "$Name başarıyla kuruldu."
    } catch {
        # Alternate method
        if ($_.Exception.Message -match '0x80073D02') {
            # If resources in use exception, fail immediately
            Handle-Error $_
            throw
        }

        try {
            $url = $AlternateUrl

            # Throw reason if alternate method is required
            if ($ThrowReason.Code -eq 0) {
                Write-Warning "$Name indirilmeye veya yüklenmeye çalışılırken hata oluştu. Alternatif yöntem deneniyor..."
            } else {
                Write-Warning $ThrowReason.Message
            }

            # If the URL is empty, throw error
            if ($url -eq "") {
                throw "URL is empty"
            }

            # Specific logic for VCLibs alternate method
            if ($Name -eq "VCLibs") {
                if ($DebugMode) {
                    Write-Output "URL: $($url)"
                }
                Write-Output "${arch} ${Name} Kuruluyor..."
                Add-AppxPackage $url -ErrorAction Stop
                Write-Output "$Name başarıyla kuruldu."
            }

            # Specific logic for UI.Xaml
            if ($Name -eq "UI.Xaml") {
                $TempFolder = Get-TempFolder

                $uiXaml = @{
                    url           = $url
                    appxFolder    = "tools/AppX/$arch/Release/"
                    appxFilename  = "Microsoft.UI.Xaml.$AppxFileVersion.appx"
                    nupkgFilename = Join-Path -Path $TempFolder -ChildPath "Microsoft.UI.Xaml.$NupkgVersion.nupkg"
                    nupkgFolder   = Join-Path -Path $TempFolder -ChildPath "Microsoft.UI.Xaml.$NupkgVersion"
                }

                # Debug
                if ($DebugMode) {
                    $formattedDebugOutput = ($uiXaml | ConvertTo-Json -Depth 10 -Compress) -replace '\\\\', '\'
                    Write-Output "uiXaml:"
                    Write-Output $formattedDebugOutput
                }

                # Downloading
                Write-Output "UI.Xaml indiriliyor..."
                if ($DebugMode) {
                    Write-Output "URL: $($uiXaml.url)"
                }
                Invoke-WebRequest -Uri $uiXaml.url -OutFile $uiXaml.nupkgFilename

                # Check if folder exists and delete if needed (will occur whether DisableCleanup is $true or $false)
                Cleanup -Path $uiXaml.nupkgFolder -Recurse

                # Extracting
                Write-Output "Ayrıştırılıyor..."
                if ($DebugMode) {
                    Write-Output "Klasörün içine: $($uiXaml.nupkgFolder)"
                }
                Add-Type -Assembly System.IO.Compression.FileSystem
                [IO.Compression.ZipFile]::ExtractToDirectory($uiXaml.nupkgFilename, $uiXaml.nupkgFolder)

                # Prep for install
                Write-Output "${arch} ${Name} Kuruluyor..."
                $XamlAppxFolder = Join-Path -Path $uiXaml.nupkgFolder -ChildPath $uiXaml.appxFolder
                $XamlAppxPath = Join-Path -Path $XamlAppxFolder -ChildPath $uiXaml.appxFilename

                # Debugging
                if ($DebugMode) { Write-Output "Kuruluyor appx Packages in: $XamlAppxFolder" }

                # Install
                Get-ChildItem -Path $XamlAppxPath -Filter *.appx | ForEach-Object {
                    if ($DebugMode) { Write-Output "Kuruluyor appx Package: $($_.Name)" }
                    Add-AppxPackage $_.FullName -ErrorAction Stop
                }
                Write-Output "UI.Xaml başarıyla kuruldu."

                # Cleanup
                if ($DisableCleanup -eq $false) {
                    Cleanup -Path $uiXaml.nupkgFilename
                    Cleanup -Path $uiXaml.nupkgFolder -Recurse $true
                }
            }
        } catch {
            # If unable to connect to remote server and Windows 10 or Server 2022, display warning message
            $ShowOldVersionMessage = $False
            if ($_.Exception.Message -match "Uzak sunucuya bağlanılamıyor") {
                # Determine the correct Windows caption and set $ShowOutput to $True if conditions are met
                if ($osVersion.Type -eq "Workstation" -and $osVersion.NumericVersion -eq 10) {
                    $WindowsCaption = "Windows 10"
                    $ShowOldVersionMessage = $True
                } elseif ($osVersion.Type -eq "Server" -and $osVersion.NumericVersion -eq 2022) {
                    $WindowsCaption = "Server 2022"
                    $ShowOldVersionMessage = $True
                }

                # Output the warning message if $ShowOldVersionMessage is $True, otherwise output the generic error message
                if ($ShowOldVersionMessage) {
                    $OldVersionMessage = "$Name dosyasını indirmek için sunucuya bağlanmada bir sorun var. Ne yazık ki bu, önkoşul sunucu URL'leriyle ilgili bilinen bir sorundur - bazen kapalı olurlar. $WindowsCaption kullandığınız için önkoşulların mağaza dışı sürümlerini kullanmanız gerekir, Windows mağazasındaki önkoşullar çalışmayacaktır, bu nedenle daha sonra tekrar denemeniz veya manuel olarak yüklemeniz gerekebilir."
                    Write-Warning $OldVersionMessage
                } else {
                    Write-Warning "$Name indirmeye veya yüklemeye çalışırken hata oluştu. Lütfen daha sonra tekrar deneyin veya $Name'i manuel olarak yükleyin."
                }
            }

            $errorHandled = Handle-Error $_
            if ($null -ne $errorHandled) {
                throw $errorHandled
            }
            $errorHandled = $null
        }
    }
}

# ============================================================================ #
# Initial checks
# ============================================================================ #

# Check for updates if -CheckForUpdate is specified
if ($CheckForUpdate) {
    CheckForUpdate -RepoOwner $RepoOwner -RepoName $RepoName -CurrentVersion $CurrentVersion -PowerShellGalleryName $PowerShellGalleryName
}

# Heading
Write-Output "winget-install $CurrentVersion"
Write-Output "Güncellemeleri kontrol etmek için winget-install -CheckForUpdate komutunu kullanabilirsiniz."


# Set OS version
$osVersion = Get-OSInfo

# Set architecture type
$arch = $osVersion.Architecture

# If it's a workstation, make sure it is Windows 10+
if ($osVersion.Type -eq "Workstation" -and $osVersion.NumericVersion -lt 10) {
    Write-Error "winget yalnızca Windows 10 veya üzeri sürümlerle uyumludur."
    exit 1
}

# If it's a workstation with Windows 10, make sure it's version 1809 or greater
if ($osVersion.Type -eq "Workstation" -and $osVersion.NumericVersion -eq 10 -and $osVersion.ReleaseId -lt 1809) {
    Write-Error "winget yalnızca Windows 10 sürüm 1809 veya üstü ile uyumludur."
    exit 1
}

# If it's a server, it needs to be 2022+
if ($osVersion.Type -eq "Server" -and $osVersion.NumericVersion -lt 2022) {
    Write-Error "winget yalnızca Windows Server 2022+ ile uyumludur."
    exit 1
}

# Check if winget is already installed
if (Get-WingetStatus) {
    if ($Force -eq $false) {
        Write-Output " ı  ,  İ"
        exit 0
    }
}

# ============================================================================ #
# Beginning of installation process
# ============================================================================ #

try {
    # ============================================================================ #
    # Install prerequisites
    # ============================================================================ #

    # VCLibs
    Install-Prerequisite -Name "VCLibs" -Version "14.00" -Url "https://store.rg-adguard.net/api/GetFiles" -AlternateUrl "https://aka.ms/Microsoft.VCLibs.$arch.14.00.Desktop.appx" -ContentType "application/x-www-form-urlencoded" -Body "type=PackageFamilyName&url=Microsoft.VCLibs.140.00_8wekyb3d8bbwe&ring=RP&lang=en-US"

    # UI.Xaml
    Install-Prerequisite -Name "UI.Xaml" -Version "2.7.3" -Url "https://store.rg-adguard.net/api/GetFiles" -AlternateUrl "https://www.nuget.org/api/v2/package/Microsoft.UI.Xaml/2.7.3" -ContentType "application/x-www-form-urlencoded" -Body "type=ProductId&url=9P5VK8KZB5QZ&ring=RP&lang=en-US" -NupkgVersion "2.7.3" -AppxFileVersion "2.7"

    # ============================================================================ #
    # Install winget
    # ============================================================================ #

    $TempFolder = Get-TempFolder

    # Output
    Write-Section "winget indiriliyor ve kuruluyor."

    Write-Output "GitHub'dan winget için indirme URL'si alınıyor..."
    $wingetUrl = Get-WingetDownloadUrl -Match "msixbundle"
    $wingetPath = Join-Path -Path $tempFolder -ChildPath "winget.msixbundle"
    $wingetLicenseUrl = Get-WingetDownloadUrl -Match "License1.xml"
    $wingetLicensePath = Join-Path -Path $tempFolder -ChildPath "license1.xml"

    # If the URL is empty, throw error
    if ($wingetUrl -eq "") {
        throw "URL hatalı"
    }

    Write-Output "winget indiriliyor..."
    if ($DebugMode) {
        Write-Output "URL: $wingetUrl"
        Write-Output "Saving as: $wingetPath"
    }
    Invoke-WebRequest -Uri $wingetUrl -OutFile $wingetPath

    Write-Output "Lisans indiriliyor..."
    if ($DebugMode) {
        Write-Output "URL: $wingetLicenseUrl"
        Write-Output "Saving as: $wingetLicensePath"
    }
    Invoke-WebRequest -Uri $wingetLicenseUrl -OutFile $wingetLicensePath

    Write-Output "winget kuruluyor..."

    # Debugging
    if ($DebugMode) {
        Write-Output "wingetPath: $wingetPath"
        Write-Output "wingetLicensePath: $wingetLicensePath"
    }

    # Try to install winget
    try {
        # Add-AppxPackage will throw an error if the app is already installed or higher version installed, so we need to catch it and continue
        Add-AppxProvisionedPackage -Online -PackagePath $wingetPath -LicensePath $wingetLicensePath -ErrorAction SilentlyContinue | Out-Null
        Write-Output "winget başarıyla kuruldu."
    } catch {
        $errorHandled = Handle-Error $_
        if ($null -ne $errorHandled) {
            throw $errorHandled
        }
        $errorHandled = $null
    }

    # Cleanup
    if ($DisableCleanup -eq $false) {
        Cleanup -Path $wingetPath
        Cleanup -Path $wingetLicensePath
    }

    # ============================================================================ #
    # PATH environment variable
    # ============================================================================ #

    # Add the WindowsApps directory to the PATH variable
    Write-Section "Mevcut değilse, geçerli kullanıcı için WindowsApps dizinini kontrol eder ve PATH değişkenine ekler..."
    $WindowsAppsPath = [IO.Path]::Combine([Environment]::GetEnvironmentVariable("LOCALAPPDATA"), "Microsoft", "WindowsApps")
    Update-PathEnvironmentVariable -NewPath $WindowsAppsPath

    # ============================================================================ #
    # Finished
    # ============================================================================ #

    Write-Section "Kurulum tamamlandı!"

    # Timeout for 5 seconds to check winget
    Write-Output "Winget'in kurulu ve çalışır durumda olup olmadığını kontrol ediliyor..."
    Start-Sleep -Seconds 3

    # Check if winget is installed
    if (Get-WingetStatus -eq $true) {
        Write-Output "winget şimdi kuruldu ve çalışıyor, devam edebilir ve kullanabilirsiniz."
    } else {
        Write-Warning "winget yüklü ancak bir komut olarak algılanmıyor. Şimdi winget'i kullanmayı deneyin. Çalışmazsa, yaklaşık 1 dakika bekleyin ve tekrar deneyin (bazen gecikebilir). Ayrıca bilgisayarınızı yeniden başlatmayı deneyin."
        Write-Warning "Bilgisayarınızı yeniden başlatırsanız ve komut hala tanınmazsa, lütfen README: https://github.com/asheroto/winget-install#troubleshooting adresindeki Sorun Giderme bölümünü okuyun."
        Write-Warning "Bu komutu çalıştırarak betiğin en son sürümüne sahip olduğunuzdan emin olun: $PowerShellGalleryName -CheckForUpdate"
    }
} catch {
    # ============================================================================ #
    # Error handling
    # ============================================================================ #

    Write-Section "UYARI! Kurulum sırasında bir hata oluştu!"
    Write-Warning "Yukarıdaki mesajlar yardımcı olmaz ve sorun devam ederse, lütfen README: https://github.com/asheroto/winget-install#troubleshooting adresindeki Sorun Giderme bölümünü okuyun."
    Write-Warning "Bu komutu çalıştırarak betiğin en son sürümüne sahip olduğunuzdan emin olun: $PowerShellGalleryName -CheckForUpdate"

    # If it's not 0x80073D02 (resources in use), show error
    if ($_.Exception.Message -notmatch '0x80073D02') {
        if ($DebugMode) {
            Write-Warning "Line number : $($_.InvocationInfo.ScriptLineNumber)"
        }
        Write-Warning "Error: $($_.Exception.Message)"
    }
}
