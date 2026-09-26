# =====================================================================================
# ADVANCED WINDOWS BOOT / BCD / SECURE BOOT / UEFI CHECK
# VERSION 6 - PER-CATEGORY SCORING, BASELINE, HARDENED INTEGRITY, ENGLISH LOCALIZATION
# Compatible Windows 10/11 - Legacy BIOS / UEFI - GPT / MBR
# =====================================================================================
# History:
#   v2 -> v3:
#     [FIX 1] $PartitionStyle initialized to $null in INITIALIZATION
#     [FIX 2] $DBXPresent initialized to $false in INITIALIZATION
#     [FIX 3] SMART: dynamic status based on HealthStatus
#     [FIX 4] HACKINTOSH: uses $BCDEntries instead of $BCD
#   v3 -> v4:
#     [NEW 1]  Timestamped report files (CSV / HTML / JSON)
#     [NEW 2]  Windows version and build number
#     [NEW 3]  bootmgfw.efi check (first link in the UEFI boot chain)
#     [NEW 4]  EFI partition free space check
#     [NEW 5]  Detection of unsigned boot drivers
#     [NEW 6]  Fast Boot detection (HiberbootEnabled)
#     [NEW 7]  System file integrity check (SFC /verifyonly)
#     [NEW 8]  Windows image check (DISM CheckHealth)
#     [NEW 9]  JSON export in addition to CSV and HTML
#     [NEW 10] Status coloring in the HTML report
#     [NEW 11] Colored console summary (ERRORS and WARNINGS only)
#   v4 -> v5:
#     [NEW 12] -Silent / -SelfTest / -Category / -SkipSlowChecks / -CreateRestorePoint parameters
#     [NEW 13] Weighted scoring PER CATEGORY in addition to the overall score (see Check-Security_Win11)
#     [NEW 14] "Critical findings" block at the top of the HTML report
#     [NEW 15] Persistent JSON baseline + comparison with the previous run
#     [NEW 16] SHA256 hash of bootmgfw.efi / winload.efi, drift tracking between runs
#     [NEW 17] DBX entry count (UEFI revocation list) + regression detection
#     [NEW 18] Detection of recent boot failures in the Kernel-Boot log
#     [NEW 19] VBS / HVCI check (Memory Integrity)
#     [NEW 20] Detection of orphaned BCD entries / abnormally large BCD store
#     [NEW 21] Last boot time (LastBootUpTime) + effective boot time
#     [NEW 22] Optional -CreateRestorePoint before DISM checks
#     [NEW 23] Migration Get-WmiObject -> Get-CimInstance (boot drivers)
#     [NEW 24] Consolidated bcdedit call (a single script-scope call)
#     [NEW 25] SVG sparkline of score history in the HTML report
#     [NEW 26] Desktop toast notification at the end of the run
#     [NEW 27] -SelfTest: 12 assertions on the critical functions
#     [NEW 28] -Silent mode: no console output, useful for scheduled tasks
#   v5 -> v5.2 (feedback from the first real run):
#     [FIX v5.2-1] BCD entry count: "Windows Boot Loader"/"identifier" are labels
#                  LOCALIZED by bcdedit (French: "Chargeur de démarrage Windows",
#                  "identificateur"...), which skewed the count to 0 on French Windows. Replaced
#                  with a GUID count (never translated), independent of the system language.
#     [FIX v5.2-2] BCD file size: the path "$env:SystemDrive\Boot\BCD" does not exist on most
#                  modern UEFI installs (the BCD lives on the EFI partition); the metric was
#                  silently disappearing. Added candidate paths + explicit INFO status if not
#                  found, instead of a silent skip.
#     [FIX v5.2-3] TPM SpecVersion could come back empty (blank report line); added an INFO fallback.
#     [FIX v5.2-4] Kernel-Boot errors: the raw counter wasn't usable for diagnosis; added the
#                  breakdown by Event ID (top 3) to the result.
#   v5.2 -> v5.3 (feedback from the second real run):
#     [FIX v5.3-1] Raw GUID count (v5.2): counted EVERY GUID in the bcdedit output (bootmgr,
#                  device options, resume objects, ramdisk, partition GUIDs referenced in
#                  "device" lines...), not specifically Windows boot entries -> false positive
#                  (10 GUIDs flagged as "orphaned" on a perfectly normal Linux + recovery
#                  dual-boot setup). Replaced with a count of "winload.efi"/"winload.exe"
#                  occurrences (a literal file path, therefore never translated, appearing once
#                  per real Windows boot entry).
#     [FIX v5.3-2] BCD file size: on most modern UEFI installs the ESP is NOT mounted under a
#                  drive letter (Windows best practice), so no candidate file path could ever
#                  find it. Replaced with a read of the object count via the live
#                  "HKLM:\BCD00000000\Objects" registry hive, always accessible regardless of
#                  the physical location of the file.
#   v5.3 -> v5.4:
#     [NEW v5.4] Kernel-Boot ID 124 errors (VBS phase verification failure): cross-diagnosis with
#                msinfo32 on this hardware confirmed an OEM firmware limitation (PCR 7 "Binding
#                not possible" + DMA protection disabled, pre-Win11-2019 GL753VD). Automatic
#                annotation added to the report to document the likely cause without having to
#                re-diagnose it on every run - the WARNING status is still shown (a known and
#                accepted hardware limitation, not hidden, same logic as the BitLocker FAIL).
#   v5.4 -> v5.5 (feedback from a real run on a BIOS/MBR machine):
#     [FIX v5.5] Recovery partition reported as "Missing" as a false positive on BIOS/MBR even
#                after a full fix (type 0x27, no drive letter, recognized by reagentc and Disk
#                Management). Cause: the test relied solely on Get-Partition.Type, which
#                translates the raw type into a readable label but does not do so reliably for
#                MBR codes (0x27 sometimes stays "Unknown"/"IFS"). Replaced with a direct test on
#                the source values .MbrType (0x27) and .GptType (Recovery GUID), which do not
#                depend on any translation. [NEW v5.5] Added an "exposed Recovery partition"
#                check (drive letter assigned = Hidden attribute likely missing), a real case
#                encountered where a restore/diskpart operation had left the partition visible
#                and mounted as D:. [NEW v5.5] Matching logic extracted into
#                Test-IsRecoveryPartition (same approach as Safe-CommandExists/Get-FileSha256),
#                covered by 3 new -SelfTest assertions (MBR 0x27, GPT GUID, negative case) to
#                catch a regression without depending on the architecture of the machine the
#                SelfTest is run on.
#   v5.5 -> v5.6 (HTML report only, no check logic changed):
#     [NEW v5.6] HTML report fully rebuilt on the visual template of Dashboard-Global_Win11 /
#                Check-Drivers_Win11 v2.0.3 (dark background, radial gradients, circular gauge
#                for the overall score, trend vs previous run, vector sparkline, weighted
#                per-category tiles with color badges and a "+N more" collapse, "Critical
#                findings" section as cards instead of a raw table, final table with status
#                pills) - visual consistency with the rest of the suite instead of the original
#                light HTML template (which, unlike Check-Drivers/Check-Network, didn't even have
#                a filter field).
#     [NEW v5.6] Filter bar + "Issues only" checkbox added (absent from the original report),
#                applied both to the category tiles and to the results table (same generic JS
#                script as the Dashboard).
#   v5.6 -> v6.0 (English localization + Check-Security visual template, console and HTML):
#     [NEW v6.0] Full script translated to English: every comment, console message, HTML label,
#                and category name (ValidateSet / CategoryWeights / CategoryOrder / report
#                columns), keeping bilingual FR/EN regex only where genuinely locale-dependent
#                (the sfc/dism raw-text fallback parsing) so the script still runs correctly,
#                unmodified, on a French-language Windows.
#     [NEW v6.0] Script self-identity renamed Check-Boot_Win11 -> Check-Boot wherever the script
#                names itself (SelfTest banner, restore point description, HTML title/H1/footer,
#                toast notification); OS-behavior mentions of "Win11"/"Windows 11" (category name,
#                compatibility check) left unchanged since they describe Windows, not the script.
#     [NEW v6.0] HTML report rebuilt on Check-Security_Win11's visual template instead of the
#                v5.6 Dashboard-style template: dark navy banner with the Windows logo and a
#                cyan/purple radial glow extended across the whole page (not just the header),
#                score shown as a horizontal bar instead of a circular gauge, and the v5.6
#                per-category tile grid replaced by an inline "Score by category" table (progress
#                bar in the row itself) - easier to scan, and consistent with the rest of the
#                suite's reports.
#     [NEW v6.0] Console output rebuilt on Check-Security's aesthetic: a framed Unicode-box
#                section banner the first time a category is hit (Show-SectionBanner), then one
#                timestamped/colored line per check (Show-CheckLine) - Add-Result now drives both
#                live instead of a single Format-Table dump and an "ITEMS NEEDING ATTENTION" list
#                at the very end. Finishes with a boxed "SUMMARY" block (totals, weighted score,
#                trend vs previous run) and a boxed "AUDIT COMPLETE" block with a text score bar
#                and the generated report paths under ">>". The old ASCII "=====" banners at
#                startup/shutdown were dropped as redundant with the new framed sections.
#     [FIX v6.0] File re-saved with a UTF-8 BOM: without it, Windows PowerShell 5.1's console
#                misreads the Unicode box-drawing/status-icon characters used by the new console
#                rendering (garbled into "â”Œ"-style mojibake) and fails to parse the script - same
#                fix already applied to Harden-TLS/Check-Security/Windows-Preflight-Cleaner for
#                the same reason.
#     [NEW v6.0] Report folder aligned with the rest of the suite: reports now go to
#                Desktop\Maintenance_Reports\Boot instead of Desktop\Rapports_Maintenance\Boot
#                (same convention already adopted by Harden-TLS/Windows-Preflight-Cleaner). File
#                names inside that folder (Rapport_Boot_*.csv/json/html, Baseline_Boot.json) are
#                unchanged.
# =====================================================================================

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$Silent,
    [switch]$SelfTest,
    [switch]$SkipSlowChecks,
    [switch]$CreateRestorePoint,
    [ValidateSet(
        "System","Firmware","Disk","BCD","Secure Boot","TPM","EFI","Legacy BIOS",
        "Secure Boot Keys","Security","Boot Drivers","Fast Boot","BitLocker","WinRE",
        "Recovery","SMART","System Integrity","Boot Order","Dual Boot","Hackintosh",
        "Win11 Compatibility","Boot Log","Summary"
    )]
    [string[]]$Category
)

#region AUTO-ELEVATION

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)

if (-not $currentPrincipal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {

    $ArgList = "-ExecutionPolicy Bypass -NoProfile -File `"$PSCommandPath`""
    if ($Silent)             { $ArgList += " -Silent" }
    if ($SelfTest)           { $ArgList += " -SelfTest" }
    if ($SkipSlowChecks)     { $ArgList += " -SkipSlowChecks" }
    if ($CreateRestorePoint) { $ArgList += " -CreateRestorePoint" }
    if ($Category)           { $ArgList += " -Category " + (($Category | ForEach-Object { "`"$_`"" }) -join ",") }

    Start-Process powershell.exe -Verb RunAs -ArgumentList $ArgList
    exit
}

Set-ExecutionPolicy Bypass -Scope Process -Force

#endregion

#region INITIALIZATION

$Results     = @()
$HealthScore = 100

# [FIX 1] Preventive script-scope initializations
$PartitionStyle = $null
$DBXPresent     = $false
$BCDEntries     = $null
$FirmwareType   = $null
$SecureBoot     = $null

# [NEW 1] Timestamp: every report carries the run date and time
$Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"

$ReportDir = "$env:USERPROFILE\Desktop\Maintenance_Reports\Boot"
if (-not (Test-Path $ReportDir)) {
    New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
}

$CsvPath      = "$ReportDir\Rapport_Boot_$Timestamp.csv"
$HtmlPath     = "$ReportDir\Rapport_Boot_$Timestamp.html"
$JsonPath     = "$ReportDir\Rapport_Boot_$Timestamp.json"
$BaselinePath = "$ReportDir\Baseline_Boot.json"

# [NEW 13] Per-category weights for weighted scoring (informative sum, not required to total 100)
$CategoryWeights = @{
    "System"               = 2
    "Firmware"              = 5
    "Disk"                = 5
    "BCD"                   = 10
    "Secure Boot"           = 10
    "TPM"                   = 6
    "EFI"                   = 8
    "Legacy BIOS"           = 4
    "Secure Boot Keys"      = 8
    "Security"              = 8
    "Boot Drivers"          = 6
    "Fast Boot"             = 3
    "BitLocker"             = 6
    "WinRE"                 = 5
    "Recovery"              = 4
    "SMART"                 = 6
    "System Integrity"     = 10
    "Boot Order"            = 2
    "Dual Boot"             = 1
    "Hackintosh"            = 1
    "Win11 Compatibility"   = 2
    "Boot Log"          = 4
}

# [NEW 13] Per-category score counter (100 = perfect, deducted independently of the overall score)
$CategoryScores = @{}
foreach ($Cat in $CategoryWeights.Keys) { $CategoryScores[$Cat] = 100 }

# [NEW v6.1] Console rendering (Check-Security-style framed section banners + live check lines):
# fixed display order used both for banner numbering and for the category column width, and a
# tracker of which category banners have already been printed this run.
$script:CategoryDisplayOrder = @(
    "System", "Firmware", "Disk", "BCD", "Secure Boot", "TPM", "EFI", "Legacy BIOS",
    "Secure Boot Keys", "Security", "Boot Drivers", "Fast Boot", "BitLocker", "WinRE",
    "Recovery", "SMART", "System Integrity", "Boot Order", "Dual Boot", "Hackintosh",
    "Win11 Compatibility", "Boot Log"
)
$script:CategoryBannerNumber = @{}
for ($i = 0; $i -lt $script:CategoryDisplayOrder.Count; $i++) {
    $script:CategoryBannerNumber[$script:CategoryDisplayOrder[$i]] = $i + 1
}
$script:CategoryPadWidth = ($script:CategoryDisplayOrder | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
$script:BannerShown = @{}

#endregion

#region FUNCTIONS

function Add-Result {

    param(
        [string]$Categorie,
        [string]$Element,
        [string]$Valeur,
        [string]$Statut
    )

    # If -Category is used, skip categories that were not requested (except "Summary", always shown)
    if ($script:Category -and $Categorie -ne "Summary" -and ($Categorie -notin $script:Category)) {
        return
    }

    $script:Results += [PSCustomObject]@{
        Categorie = $Categorie
        Element   = $Element
        Valeur    = $Valeur
        Statut    = $Statut
    }

    switch ($Statut) {

        "ERROR" {
            $script:HealthScore -= 15
            if ($script:CategoryScores.ContainsKey($Categorie)) {
                $script:CategoryScores[$Categorie] -= 30
            }
        }

        "WARNING" {
            $script:HealthScore -= 5
            if ($script:CategoryScores.ContainsKey($Categorie)) {
                $script:CategoryScores[$Categorie] -= 10
            }
        }
    }

    # [NEW v6.1] Live console rendering, Check-Security style: a framed section banner the first
    # time a category is hit, then one timestamped/colored line per check. "Summary" rows are the
    # final aggregate (score, per-category totals) rather than individual checks, so they are
    # skipped here and rendered separately by the SUMMARY/AUDIT COMPLETE blocks in DISPLAY/END.
    if ($Categorie -ne "Summary") {
        Show-SectionBanner -Categorie $Categorie
        Show-CheckLine -Categorie $Categorie -Element $Element -Valeur $Valeur -Statut $Statut
    }
}

function Show-SectionBanner {

    param([string]$Categorie)

    if ($script:Silent -or $script:SelfTest) { return }
    if ($script:BannerShown.ContainsKey($Categorie)) { return }
    $script:BannerShown[$Categorie] = $true

    $Number = if ($script:CategoryBannerNumber.ContainsKey($Categorie)) { $script:CategoryBannerNumber[$Categorie] } else { "" }
    $Title  = "$Number. $($Categorie.ToUpper())"
    $Inner  = $Title.Length + 2

    Write-Host ""
    Write-Host ("┌" + ("─" * $Inner) + "┐") -ForegroundColor Cyan
    Write-Host ("│ $Title │") -ForegroundColor Cyan
    Write-Host ("└" + ("─" * $Inner) + "┘") -ForegroundColor Cyan
    Write-Host ""
}

function Show-CheckLine {

    param(
        [string]$Categorie,
        [string]$Element,
        [string]$Valeur,
        [string]$Statut
    )

    if ($script:Silent -or $script:SelfTest) { return }

    $Icon  = switch ($Statut) { "OK" { "✓" } "WARNING" { "!" } "ERROR" { "X" } default { "·" } }
    $Color = switch ($Statut) { "OK" { "Green" } "WARNING" { "Yellow" } "ERROR" { "Red" } default { "Gray" } }

    $Time      = Get-Date -Format "HH:mm:ss"
    $CatPadded = $Categorie.PadRight($script:CategoryPadWidth)

    Write-Host "$Time  " -NoNewline -ForegroundColor DarkGray
    Write-Host "$Icon  " -NoNewline -ForegroundColor $Color
    Write-Host "$CatPadded" -NoNewline -ForegroundColor Cyan
    Write-Host "  | " -NoNewline -ForegroundColor DarkGray
    Write-Host "$Element" -NoNewline -ForegroundColor White
    Write-Host " : " -NoNewline -ForegroundColor DarkGray
    Write-Host "$Valeur" -ForegroundColor $Color
}

function Show-Step {

    param(
        [string]$Text,
        [int]$Percent
    )

    if (-not $script:Silent) {
        Write-Progress `
            -Activity "Windows boot health analysis" `
            -Status $Text `
            -PercentComplete $Percent
    }
}

function Write-Info {
    param([string]$Text, [string]$Color = "White")
    if (-not $script:Silent) {
        Write-Host $Text -ForegroundColor $Color
    }
}

function Safe-CommandExists {

    param(
        [string]$Command
    )

    return [bool](Get-Command $Command -ErrorAction SilentlyContinue)
}

function Test-IsRecoveryPartition {

    # [NEW v5.5] Extracted into its own function so it can be tested with -SelfTest on both
    # architectures (MBR and GPT) without depending on the actual disk of the machine running the script.
    param($Partition)

    return (
        $Partition.Type -eq "Recovery" -or
        $Partition.MbrType -eq 0x27 -or
        ($Partition.GptType -match "(?i)de94bba4-06d1-4d40-a16a-bfd50179d6ac")
    )
}

function Get-FileSha256 {

    param([string]$Path)

    try {
        if (Test-Path $Path) {
            return (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash
        }
    }
    catch {}

    return $null
}

#endregion

#region SELFTEST

if ($SelfTest) {

    Write-Host ""
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host " SELFTEST - Check-Boot v6.0"
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host ""

    $TestsPassed = 0
    $TestsTotal  = 0

    function Assert-True {
        param([string]$Name, [bool]$Condition)
        $script:TestsTotal++
        if ($Condition) {
            $script:TestsPassed++
            Write-Host "[PASS] $Name" -ForegroundColor Green
        }
        else {
            Write-Host "[FAIL] $Name" -ForegroundColor Red
        }
    }

    # 1. Add-Result correctly feeds $Results and deducts the overall score
    $Results = @()
    $HealthScore = 100
    $CategoryScores["BCD"] = 100
    Add-Result "BCD" "Test" "Value" "ERROR"
    Assert-True "Add-Result adds a row" ($Results.Count -eq 1)
    Assert-True "Add-Result deducts 15 pts (ERROR) from the overall score" ($HealthScore -eq 85)
    Assert-True "Add-Result deducts 30 pts (ERROR) from the category score" ($CategoryScores["BCD"] -eq 70)

    # 2. WARNING
    $HealthScore = 100
    $CategoryScores["TPM"] = 100
    Add-Result "TPM" "Test" "Value" "WARNING"
    Assert-True "Add-Result deducts 5 pts (WARNING) from the overall score" ($HealthScore -eq 95)
    Assert-True "Add-Result deducts 10 pts (WARNING) from the category score" ($CategoryScores["TPM"] -eq 90)

    # 3. -Category filtering
    $Results = @()
    $script:Category = @("BCD")
    Add-Result "TPM" "Test" "Value" "OK"
    Assert-True "Add-Result filters out a category that was not requested" ($Results.Count -eq 0)
    Add-Result "BCD" "Test" "Value" "OK"
    Assert-True "Add-Result keeps a requested category" ($Results.Count -eq 1)
    Add-Result "Summary" "Test" "Value" "OK"
    Assert-True "Add-Result always keeps 'Summary'" ($Results.Count -eq 2)
    # [FIX v5.1] $Category carries a [ValidateSet]: reassigning $null to $script:Category triggers
    # a MetadataError (the set does not contain $null). An empty array passes validation
    # (nothing to check) and stays "falsy" for the `if ($script:Category)` test in the main code.
    $script:Category = @()

    # 4. Safe-CommandExists
    Assert-True "Safe-CommandExists detects an existing command (Get-Date)" (Safe-CommandExists "Get-Date")
    Assert-True "Safe-CommandExists rejects a non-existent command" (-not (Safe-CommandExists "Nonexistent-Command-XYZ"))

    # 5. Get-FileSha256
    $TmpFile = Join-Path $env:TEMP "selftest_boot_v5.tmp"
    "test" | Out-File $TmpFile -Encoding ASCII
    $Hash = Get-FileSha256 -Path $TmpFile
    Assert-True "Get-FileSha256 returns a 64-character hash" ($Hash -and $Hash.Length -eq 64)
    Remove-Item $TmpFile -ErrorAction SilentlyContinue
    Assert-True "Get-FileSha256 returns `$null for a missing file" ((Get-FileSha256 -Path "C:\Nonexistent_XYZ.efi") -eq $null)

    # 6. ReportDir created
    Assert-True "The report folder exists" (Test-Path $ReportDir)

    # 7. Test-IsRecoveryPartition (MBR + GPT, without depending on the actual machine)
    $FakeMbr27 = [PSCustomObject]@{ Type = "Unknown"; MbrType = 0x27; GptType = $null }
    $FakeGpt   = [PSCustomObject]@{ Type = "Unknown"; MbrType = $null; GptType = "de94bba4-06d1-4d40-a16a-bfd50179d6ac" }
    $FakeAutre = [PSCustomObject]@{ Type = "Basic"; MbrType = 0x07; GptType = $null }

    Assert-True "Test-IsRecoveryPartition detects MBR 0x27" (Test-IsRecoveryPartition $FakeMbr27)
    Assert-True "Test-IsRecoveryPartition detects the GPT Recovery GUID" (Test-IsRecoveryPartition $FakeGpt)
    Assert-True "Test-IsRecoveryPartition rejects a normal partition" (-not (Test-IsRecoveryPartition $FakeAutre))

    Write-Host ""
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host " RESULT: $TestsPassed / $TestsTotal tests passed" -ForegroundColor $(if ($TestsPassed -eq $TestsTotal) { "Green" } else { "Red" })
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host ""

    exit $(if ($TestsPassed -eq $TestsTotal) { 0 } else { 1 })
}

#endregion

#region STARTUP

if (-not $Silent) { Clear-Host }

Write-Info ""
Write-Info "Check-Boot v6.0 — advanced Windows boot health analysis" "Cyan"

#endregion

#region RESTORE POINT

# [NEW 22] Optional restore point before the DISM checks
if ($CreateRestorePoint) {

    Show-Step "Creating restore point..." 1

    try {
        Enable-ComputerRestore -Drive "$env:SystemDrive\" -ErrorAction SilentlyContinue
        Checkpoint-Computer -Description "Check-Boot v5 - before analysis" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        Add-Result "System" "Restore point" "Created" "OK"
    }
    catch {
        Add-Result "System" "Restore point" "Creation failed (Windows frequency limited to 1/24h?)" "INFO"
    }
}

#endregion

#region WINDOWS VERSION

# [NEW 2] Retrieves the Windows version and build to give the report context
Show-Step "Detecting Windows version..." 3

try {

    $OSInfo     = Get-CimInstance Win32_OperatingSystem
    $WinCaption = $OSInfo.Caption
    $WinBuild   = $OSInfo.BuildNumber
    $WinVersion = "$WinCaption (Build $WinBuild)"

    Add-Result "System" "Windows version" $WinVersion "OK"

    # [NEW 21] Last boot time + uptime duration
    $LastBoot = $OSInfo.LastBootUpTime
    $Uptime   = (Get-Date) - $LastBoot

    Add-Result "System" "Last boot" "$($LastBoot.ToString('dd/MM/yyyy HH:mm')) (uptime: $([Math]::Round($Uptime.TotalHours,1))h)" "OK"
}
catch {

    Add-Result "System" "Windows version" "Could not be detected" "INFO"
}

#endregion

#region FIRMWARE

Show-Step "Detecting firmware..." 5

try {

    $FirmwareType = $null

    if (Safe-CommandExists "Get-ComputerInfo") {

        $ComputerInfo = Get-ComputerInfo
        $FirmwareType = $ComputerInfo.BiosFirmwareType
    }

    if (-not $FirmwareType) {

        if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State") {

            $FirmwareType = "UEFI"
        }
        else {

            $FirmwareType = "Legacy"
        }
    }

    Add-Result "Firmware" "Firmware type" $FirmwareType "OK"

}
catch {

    Add-Result "Firmware" "Firmware type" "Could not be detected" "ERROR"
}

#endregion

#region SYSTEM PARTITION

Show-Step "Analyzing system partition..." 10

try {

    $SystemLetter = $env:SystemDrive.Replace(":", "")

    $SystemPartition = Get-Partition | Where-Object {
        $_.DriveLetter -eq $SystemLetter
    }

    if ($SystemPartition) {

        $Disk = Get-Disk -Number $SystemPartition.DiskNumber

        # [FIX 1] $PartitionStyle assigned here, initialized earlier to guarantee
        # its availability in the WIN11 COMPATIBILITY region
        $PartitionStyle = $Disk.PartitionStyle

        Add-Result "Disk" "Partition type" $PartitionStyle "OK"
    }
    else {

        Add-Result "Disk" "System partition" "Not found" "ERROR"
    }
}
catch {

    Add-Result "Disk" "Partition analysis" "Detection error" "ERROR"
}

#endregion

#region BCD

# [NEW 24] A single bcdedit /enum all call, shared across all the regions that need it
# (BCD, DUAL BOOT, HACKINTOSH, BOOT ORDER)
Show-Step "Analyzing BCD..." 20

try {

    $BCDEntries  = bcdedit /enum all 2>&1
    $BCDExitCode = $LASTEXITCODE
    $BCD         = $BCDEntries

    if ($BCDExitCode -eq 0) {

        Add-Result "BCD" "BCD access" "Accessible" "OK"

        if ($BCD -match "winload\.efi") {

            Add-Result "Bootloader" "Bootloader type" "winload.efi" "OK"
        }
        elseif ($BCD -match "winload\.exe") {

            Add-Result "Bootloader" "Bootloader type" "winload.exe" "OK"
        }
        else {

            Add-Result "Bootloader" "Bootloader type" "Unknown" "ERROR"
        }

        if ($BCD -match "\{bootmgr\}") {

            Add-Result "BCD" "Boot Manager" "Present" "OK"
        }
        else {

            Add-Result "BCD" "Boot Manager" "Missing" "ERROR"
        }


        # [NEW 20] Detection of orphaned BCD entries / abnormally large store
        try {

            # [FIX v5.3] The raw GUID count (v5.2) counted EVERY GUID present in the bcdedit
            # output (bootmgr, device options, resume objects, ramdisk, partition GUIDs referenced
            # in "device" lines...), not specifically Windows boot entries. Result: 10 GUIDs
            # detected on a perfectly normal Linux + recovery dual-boot config, falsely flagged as
            # an "accumulation of orphaned entries". Now targets "winload.efi"/"winload.exe", a
            # literal file path (therefore never translated) that appears once per real Windows
            # boot entry - the relevant metric for detecting an accumulation of orphaned OS
            # entries after repeated reinstalls/restores.
            $OsLoaderCount = ([regex]::Matches($BCD, "winload\.(efi|exe)")).Count

            if ($OsLoaderCount -gt 4) {

                Add-Result "BCD" "Windows boot entries (winload)" "$OsLoaderCount entries detected (likely accumulation of orphaned entries)" "WARNING"
            }
            else {

                Add-Result "BCD" "Windows boot entries (winload)" "$OsLoaderCount entry/entries" "OK"
            }

            # [FIX v5.3] On most modern UEFI installs, the EFI partition is NOT mounted under a
            # drive letter (Windows security best practice), so the candidate file paths (v5.2)
            # never find it. The BCD, however, is always readable via the live
            # "HKLM:\BCD00000000" registry hive, regardless of the physical location of the file -
            # a much more reliable source.
            try {

                $BCDObjects = Get-ChildItem -Path "HKLM:\BCD00000000\Objects" -ErrorAction Stop
                $BCDObjectCount = $BCDObjects.Count

                # A system with recovery + dual-boot legitimately accumulates bootmgr, several
                # osloaders, their associated "device options", resume objects and ramdisk: a
                # clean system already sits around 10-15 objects. Threshold raised accordingly.
                if ($BCDObjectCount -gt 25) {

                    Add-Result "BCD" "BCD objects (live registry)" "$BCDObjectCount objects - possible accumulation, check with 'bcdedit /enum all'" "WARNING"
                }
                else {

                    Add-Result "BCD" "BCD objects (live registry)" "$BCDObjectCount objects" "OK"
                }
            }
            catch {

                Add-Result "BCD" "BCD objects (live registry)" "HKLM:\BCD00000000 hive not accessible" "INFO"
            }
        }
        catch {

            Add-Result "BCD" "BCD size/entries analysis" "Could not be measured" "INFO"
        }
    }
    else {

        Add-Result "BCD" "BCD access" "Corrupted or not accessible" "ERROR"
    }
}
catch {

    Add-Result "BCD" "BCD analysis" "Read error" "ERROR"
}

#endregion

#region SECURE BOOT

Show-Step "Analyzing Secure Boot..." 30

$SecureBoot = $null

if ($FirmwareType -eq "UEFI") {

    try {

        if (Safe-CommandExists "Confirm-SecureBootUEFI") {

            $SecureBoot = Confirm-SecureBootUEFI

            if ($SecureBoot -eq $true) {

                Add-Result "Secure Boot" "State" "Enabled" "OK"
            }
            else {

                Add-Result "Secure Boot" "State" "Disabled" "WARNING"
            }
        }
        else {

            Add-Result "Secure Boot" "State" "Command not supported" "INFO"
        }
    }
    catch {

        Add-Result "Secure Boot" "State" "Could not be determined" "INFO"
    }
}
else {

    Add-Result "Secure Boot" "State" "Not applicable in Legacy BIOS" "INFO"
}

#endregion

#region TPM

Show-Step "Analyzing TPM..." 35

try {

    if (Safe-CommandExists "Get-Tpm") {

        $TPM = Get-Tpm

        if ($TPM.TpmPresent) {

            Add-Result "TPM" "TPM present" "Present" "OK"

            # [FIX v5.2] SpecVersion can come back empty depending on the TPM driver/Windows
            # version; this avoids a blank report line and falls back to an explicit status.
            if ($TPM.SpecVersion) {
                Add-Result "TPM" "TPM version" $TPM.SpecVersion "OK"
            }
            else {
                Add-Result "TPM" "TPM version" "Not reported by the driver" "INFO"
            }
        }
        else {

            Add-Result "TPM" "TPM present" "Not present" "WARNING"
        }
    }
    else {

        Add-Result "TPM" "TPM state" "Command not available" "INFO"
    }
}
catch {

    Add-Result "TPM" "TPM state" "Read error" "ERROR"
}

#endregion

#region EFI

Show-Step "Analyzing EFI..." 45

# [NEW 16] Boot binary paths used for the SHA256 hash (computed even outside UEFI where possible)
$WinloadEfiPath   = "$env:windir\System32\winload.efi"
$BootmgfwPathMain = "$env:SystemDrive\EFI\Microsoft\Boot\bootmgfw.efi"
$BootmgfwFallback = "$env:windir\Boot\EFI\bootmgfw.efi"

if ($FirmwareType -eq "UEFI") {

    try {

        $EFIPartition = Get-Partition | Where-Object {
            $_.GptType -match "(?i)c12a7328"
        }

        if ($EFIPartition) {

            Add-Result "EFI" "EFI partition" "Present" "OK"

            # [NEW 4] Free space check on the EFI partition
            # A full EFI partition blocks Windows updates
            try {

                $EFIVolume = Get-Volume -Partition $EFIPartition -ErrorAction Stop

                if ($EFIVolume) {

                    $EFIFreeMB = [Math]::Round($EFIVolume.SizeRemaining / 1MB, 1)

                    if ($EFIFreeMB -ge 50) {

                        Add-Result "EFI" "EFI free space" "$EFIFreeMB MB available" "OK"
                    }
                    elseif ($EFIFreeMB -ge 10) {

                        Add-Result "EFI" "EFI free space" "$EFIFreeMB MB available" "WARNING"
                    }
                    else {

                        Add-Result "EFI" "EFI free space" "$EFIFreeMB MB available - Critical" "ERROR"
                    }
                }
            }
            catch {

                Add-Result "EFI" "EFI free space" "Could not be measured" "INFO"
            }
        }
        else {

            Add-Result "EFI" "EFI partition" "Missing" "ERROR"
        }

        if (Test-Path $WinloadEfiPath) {

            Add-Result "EFI" "winload.efi" "Present" "OK"
        }
        else {

            Add-Result "EFI" "winload.efi" "Missing" "ERROR"
        }

        # [NEW 3] bootmgfw.efi check: first link in the UEFI boot chain
        # Its absence prevents any boot even if winload.efi is present
        $BootmgfwActivePath = $null

        if (Test-Path $BootmgfwPathMain) {

            Add-Result "EFI" "bootmgfw.efi" "Present" "OK"
            $BootmgfwActivePath = $BootmgfwPathMain
        }
        else {

            # Try the alternate system drive (EFI partition not mounted)
            # Also try the native Windows directory as a fallback
            if (Test-Path $BootmgfwFallback) {

                Add-Result "EFI" "bootmgfw.efi" "Present (fallback)" "OK"
                $BootmgfwActivePath = $BootmgfwFallback
            }
            else {

                Add-Result "EFI" "bootmgfw.efi" "Missing or EFI partition not mounted" "WARNING"
            }
        }

        # [NEW 16] SHA256 hash of the boot binaries + comparison with the previous baseline
        try {

            $WinloadHash   = Get-FileSha256 -Path $WinloadEfiPath
            $BootmgfwHash  = if ($BootmgfwActivePath) { Get-FileSha256 -Path $BootmgfwActivePath } else { $null }

            if ($WinloadHash) {
                Add-Result "EFI" "SHA256 winload.efi" $WinloadHash "OK"
            }
            if ($BootmgfwHash) {
                Add-Result "EFI" "SHA256 bootmgfw.efi" $BootmgfwHash "OK"
            }

            if (Test-Path $BaselinePath) {

                $PrevBaseline = Get-Content $BaselinePath -Raw -ErrorAction Stop | ConvertFrom-Json

                if ($PrevBaseline.WinloadHash -and $WinloadHash -and $PrevBaseline.WinloadHash -ne $WinloadHash) {
                    Add-Result "EFI" "winload.efi drift" "Hash differs from the previous run (likely Windows update, to confirm)" "WARNING"
                }

                if ($PrevBaseline.BootmgfwHash -and $BootmgfwHash -and $PrevBaseline.BootmgfwHash -ne $BootmgfwHash) {
                    Add-Result "EFI" "bootmgfw.efi drift" "Hash differs from the previous run (likely Windows update, to confirm)" "WARNING"
                }
            }
        }
        catch {

            Add-Result "EFI" "Boot binary hashes" "Could not be computed or compared" "INFO"
        }
    }
    catch {

        Add-Result "EFI" "EFI analysis" "Detection error" "ERROR"
    }
}

#endregion

#region LEGACY BIOS

Show-Step "Analyzing Legacy BIOS..." 50

if ($FirmwareType -eq "Legacy") {

    try {

        if (Test-Path "$env:windir\System32\winload.exe") {

            Add-Result "Legacy BIOS" "winload.exe" "Present" "OK"
        }
        else {

            Add-Result "Legacy BIOS" "winload.exe" "Missing" "ERROR"
        }
    }
    catch {

        Add-Result "Legacy BIOS" "Bootloader analysis" "Error" "ERROR"
    }
}

#endregion

#region SECURE BOOT KEYS

Show-Step "Analyzing Secure Boot keys..." 60

$DBXCount = 0

if ($FirmwareType -eq "UEFI") {

    try {

        $SecureBootEnabled = $false

        try {

            $SecureBootEnabled = Confirm-SecureBootUEFI

        }
        catch {}

        $DBPresent  = $false
        $KEKPresent = $false

        # [FIX 2] $DBXPresent reassigned here (already initialized to $false in INITIALIZATION)
        $DBXPresent = $false

        try {

            $DB = Get-SecureBootUEFI -Name db -ErrorAction Stop

            if ($DB) {
                $DBPresent = $true
            }

        }
        catch {}

        try {

            $KEK = Get-SecureBootUEFI -Name KEK -ErrorAction Stop

            if ($KEK) {
                $KEKPresent = $true
            }

        }
        catch {}

        try {

            $DBX = Get-SecureBootUEFI -Name dbx -ErrorAction Stop

            if ($DBX) {
                $DBXPresent = $true
                # [NEW 17] Size of the DBX content as a proxy for the number of revocation entries
                $DBXCount = $DBX.Bytes.Count
            }

        }
        catch {}

        if ($SecureBootEnabled) {

            Add-Result `
                "Secure Boot Keys" `
                "Secure Boot state" `
                "Secure Boot active" `
                "OK"
        }
        else {

            Add-Result `
                "Secure Boot Keys" `
                "Secure Boot state" `
                "Secure Boot inactive" `
                "WARNING"
        }

        if ($DBPresent) {

            Add-Result "Secure Boot Keys" "DB store"  "Present" "OK"
        }
        else {

            Add-Result "Secure Boot Keys" "DB store"  "Missing or not accessible" "WARNING"
        }

        if ($KEKPresent) {

            Add-Result "Secure Boot Keys" "KEK store" "Present" "OK"
        }
        else {

            Add-Result "Secure Boot Keys" "KEK store" "Missing or not accessible" "WARNING"
        }

        if ($DBXPresent) {

            Add-Result "Secure Boot Keys" "DBX store" "Present ($DBXCount bytes)" "OK"

            # [NEW 17] Regression detected if the DBX has shrunk since the previous run
            # (a shrinking DBX is abnormal: the revocation list only ever grows)
            try {

                if (Test-Path $BaselinePath) {

                    $PrevBaseline = Get-Content $BaselinePath -Raw -ErrorAction Stop | ConvertFrom-Json

                    if ($PrevBaseline.DBXSize -and $DBXCount -lt $PrevBaseline.DBXSize) {

                        Add-Result "Secure Boot Keys" "DBX regression" "DBX size smaller than the previous run ($DBXCount < $($PrevBaseline.DBXSize)) - abnormal" "WARNING"
                    }
                    elseif ($PrevBaseline.DBXSize -and $DBXCount -gt $PrevBaseline.DBXSize) {

                        Add-Result "Secure Boot Keys" "DBX update" "Revocation list grown since the previous run" "OK"
                    }
                }
            }
            catch {}
        }
        else {

            Add-Result "Secure Boot Keys" "DBX store" "Missing or not accessible" "WARNING"
        }

    }
    catch {

        Add-Result `
            "Secure Boot Keys" `
            "Secure Boot analysis" `
            "Could not be analyzed" `
            "INFO"
    }
}

#endregion

#region BLACKLOTUS

Show-Step "Analyzing BlackLotus..." 65

try {

    if ($FirmwareType -eq "UEFI") {

        # $SecureBoot and $DBXPresent are guaranteed to be initialized (see INITIALIZATION + dedicated regions)
        if ($SecureBoot -eq $true -and $DBXPresent -eq $true) {

            Add-Result "Security" "BlackLotus protection" "Mitigation present" "OK"
        }
        else {

            Add-Result "Security" "BlackLotus protection" "Protection potentially incomplete" "WARNING"
        }
    }
}
catch {

    Add-Result "Security" "BlackLotus" "Could not be determined" "INFO"
}

#endregion

#region VBS / HVCI

# [NEW 19] Virtualization Based Security / Memory Integrity (HVCI)
# Tied to the secure boot path: relies on Secure Boot + UEFI Lock
Show-Step "Analyzing VBS / HVCI..." 67

try {

    if (Safe-CommandExists "Get-CimInstance") {

        $DeviceGuard = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop

        $VBSRunning = $DeviceGuard.VirtualizationBasedSecurityStatus
        # 0 = Off / 1 = Enabled but not running / 2 = Running

        if ($VBSRunning -eq 2) {

            Add-Result "Security" "VBS (Virtualization Based Security)" "Active" "OK"
        }
        elseif ($VBSRunning -eq 1) {

            Add-Result "Security" "VBS (Virtualization Based Security)" "Enabled but not started (reboot required?)" "WARNING"
        }
        else {

            Add-Result "Security" "VBS (Virtualization Based Security)" "Inactive" "INFO"
        }

        $RunningServices = $DeviceGuard.SecurityServicesRunning

        if ($RunningServices -contains 2) {

            Add-Result "Security" "HVCI (Memory Integrity)" "Active" "OK"
        }
        else {

            Add-Result "Security" "HVCI (Memory Integrity)" "Inactive" "INFO"
        }
    }
    else {

        Add-Result "Security" "VBS / HVCI" "WMI class not available" "INFO"
    }
}
catch {

    Add-Result "Security" "VBS / HVCI" "Could not be determined" "INFO"
}

#endregion

#region BOOT DRIVERS

# [NEW 5] Detects unsigned boot-time drivers (BootStart / SystemStart)
# These drivers are a prime attack surface for rootkits
# [NEW 23] Migration Get-WmiObject -> Get-CimInstance
Show-Step "Analyzing boot drivers..." 68

try {

    $BootDrivers = Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop |
        Where-Object { $_.StartMode -eq "Boot" -or $_.StartMode -eq "System" }

    $UnsignedDrivers = @()

    foreach ($Driver in $BootDrivers) {

        try {

            if ($Driver.PathName) {

                # Normalize the path (remove the \??\ prefix)
                $DriverPath = $Driver.PathName -replace '^\\\?\?\\', ''

                if (Test-Path $DriverPath) {

                    $Sig = Get-AuthenticodeSignature -FilePath $DriverPath -ErrorAction SilentlyContinue

                    if ($Sig -and $Sig.Status -ne "Valid") {

                        $UnsignedDrivers += $Driver.DisplayName
                    }
                }
            }
        }
        catch {}
    }

    if ($UnsignedDrivers.Count -eq 0) {

        Add-Result "Boot Drivers" "Unsigned drivers" "None detected" "OK"
    }
    else {

        $UnsignedList = $UnsignedDrivers -join ", "
        Add-Result "Boot Drivers" "Unsigned drivers" $UnsignedList "WARNING"
    }
}
catch {

    Add-Result "Boot Drivers" "Driver analysis" "Could not be analyzed" "INFO"
}

#endregion

#region FAST BOOT

# [NEW 6] Fast Boot detection (Windows fast startup)
# Fast Boot does not perform a full shutdown and can mask boot issues
Show-Step "Analyzing Fast Boot..." 70

try {

    $HiberbootKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"

    if (Test-Path $HiberbootKey) {

        $HiberbootEnabled = (Get-ItemProperty -Path $HiberbootKey -Name HiberbootEnabled -ErrorAction Stop).HiberbootEnabled

        if ($HiberbootEnabled -eq 1) {

            Add-Result "Fast Boot" "Fast startup" "Enabled (incomplete shutdown)" "WARNING"
        }
        else {

            Add-Result "Fast Boot" "Fast startup" "Disabled" "OK"
        }
    }
    else {

        Add-Result "Fast Boot" "Fast startup" "Registry key missing" "INFO"
    }
}
catch {

    Add-Result "Fast Boot" "Fast Boot analysis" "Could not be determined" "INFO"
}

#endregion

#region BITLOCKER

Show-Step "Analyzing BitLocker..." 73

try {

    if (Safe-CommandExists "Get-BitLockerVolume") {

        $BitLocker = Get-BitLockerVolume -MountPoint $env:SystemDrive

        if ($BitLocker.ProtectionStatus -eq 1) {

            Add-Result "BitLocker" "Protection" "Enabled" "OK"
        }
        else {

            Add-Result "BitLocker" "Protection" "Disabled" "WARNING"
        }
    }
    else {

        Add-Result "BitLocker" "State" "Command not available" "INFO"
    }
}
catch {

    Add-Result "BitLocker" "BitLocker analysis" "Read error" "INFO"
}

#endregion

#region WINRE

Show-Step "Analyzing WinRE..." 76

try {

    $WinRE = reagentc /info

    if ($WinRE -match "Enabled") {

        Add-Result "WinRE" "Recovery environment" "Enabled" "OK"
    }
    else {

        Add-Result "WinRE" "Recovery environment" "Disabled" "WARNING"
    }
}
catch {

    Add-Result "WinRE" "WinRE analysis" "Read error" "ERROR"
}

#endregion

#region RECOVERY

Show-Step "Analyzing Recovery..." 78

try {

    # [FIX v5.5] On MBR disks, Get-Partition.Type does not reliably translate the MBR code 0x27
    # into the "Recovery" label (it sometimes stays "Unknown"/"IFS" even when MbrType is indeed
    # 0x27, and even when reagentc + Disk Management officially recognize the partition as a
    # "Recovery partition"). Testing .Type only -> systematic false negative on BIOS/MBR. Added a
    # direct test on .MbrType (0x27) and .GptType (Recovery GUID), which are the source values and
    # not a translation.
    $Recovery = Get-Partition | Where-Object { Test-IsRecoveryPartition $_ }

    if ($Recovery) {

        Add-Result "Recovery" "Recovery partition" "Present" "OK"

        # [NEW v5.5] A Recovery partition with an assigned drive letter is visible in File Explorer
        # and treated as an ordinary data volume by Windows: a sign of incorrect attributes
        # (missing Hidden flag), even if the MBR/GPT type is correct.
        foreach ($Part in $Recovery) {

            if ($Part.DriveLetter) {

                Add-Result "Recovery" "Recovery partition exposure" "Letter $($Part.DriveLetter): assigned - partition visible in File Explorer (Hidden attribute likely missing)" "WARNING"
            }
        }
    }
    else {

        Add-Result "Recovery" "Recovery partition" "Missing" "WARNING"
    }
}
catch {

    Add-Result "Recovery" "Recovery analysis" "Detection error" "ERROR"
}

#endregion

#region SMART

Show-Step "Analyzing SMART..." 80

try {

    if (Safe-CommandExists "Get-PhysicalDisk") {

        $SMART = Get-PhysicalDisk -ErrorAction Stop

        foreach ($DiskItem in $SMART) {

            # [FIX 3] Dynamic status: the health score reflects the actual disk state
            $SmartStatut = switch ($DiskItem.HealthStatus) {

                "Healthy"   { "OK" }
                "Warning"   { "WARNING" }
                default     { "ERROR" }
            }

            Add-Result `
                "SMART" `
                $DiskItem.FriendlyName `
                $DiskItem.HealthStatus `
                $SmartStatut
        }
    }
    else {

        Add-Result "SMART" "Disk state" "Command not available" "INFO"
    }
}
catch {

    Add-Result "SMART" "Disk state" "API not supported" "INFO"
}

#endregion

#region SFC

# [NEW 7] System file integrity check via SFC /verifyonly
# A failing boot often stems from corrupted system files
# [NEW 12] Slow step: skipped if -SkipSlowChecks
if (-not $SkipSlowChecks) {

    Show-Step "Running SFC..." 83

    try {

        $SFCOutput = & sfc /verifyonly 2>&1
        $SFCExitCode = $LASTEXITCODE

        # [FIX] sfc.exe switches to UTF-16LE output as soon as stdout is redirected (the case here
        # via 2>&1). PowerShell redecodes this stream using the console's 8-bit OEM encoding,
        # which inserts a NUL character after every letter (confirmed by diagnosis:
        # "L\0e\0 \0p\0r\0o\0g..."). These NULs are stripped to recover the original text before
        # comparison.
        $SFCString = ($SFCOutput | Out-String) -replace "`0", ""

        if (
            $SFCString -match "did not find any integrity violations" -or
            $SFCString -match "aucune violation" -or
            $SFCString -match "n'a trouvé aucune" -or
            $SFCString -match "no integrity violations"
        ) {

            Add-Result "System Integrity" "SFC /verifyonly" "No violations detected" "OK"
        }
        elseif (
            $SFCString -match "found corrupt" -or
            $SFCString -match "a trouvé des fichiers" -or
            $SFCString -match "integrity violations"
        ) {

            Add-Result "System Integrity" "SFC /verifyonly" "Corrupted files detected" "ERROR"
        }
        else {

            Add-Result "System Integrity" "SFC /verifyonly" "Indeterminate result" "INFO"
        }
    }
    catch {

        Add-Result "System Integrity" "SFC /verifyonly" "Could not be run" "INFO"
    }
}
else {

    Add-Result "System Integrity" "SFC /verifyonly" "Skipped (-SkipSlowChecks)" "INFO"
}

#endregion

#region DISM

# [NEW 8] Windows image check via DISM /CheckHealth
# Complements SFC: checks the state of the Windows component store
# [NEW 12] Slow step: skipped if -SkipSlowChecks
if (-not $SkipSlowChecks) {

    Show-Step "Running DISM..." 87

    try {

        # [FIX] Uses the structured cmdlet from the Dism module rather than parsing dism.exe's
        # localized text output: it returns a status (ImageHealthState) independent of language
        # and encoding, avoiding any wording or codepage issue.
        $DismResult = Repair-WindowsImage -Online -CheckHealth -ErrorAction Stop

        switch ($DismResult.ImageHealthState) {

            "Healthy" {
                Add-Result "System Integrity" "DISM CheckHealth" "Image healthy" "OK"
            }
            "Repairable" {
                Add-Result "System Integrity" "DISM CheckHealth" "Repairable corruption detected" "WARNING"
            }
            "NonRepairable" {
                Add-Result "System Integrity" "DISM CheckHealth" "Non-repairable corruption" "ERROR"
            }
            default {
                Add-Result "System Integrity" "DISM CheckHealth" "Indeterminate result ($($DismResult.ImageHealthState))" "INFO"
            }
        }
    }
    catch {

        # Fall back to dism.exe if the Repair-WindowsImage cmdlet is unavailable (older system, missing module...)
        try {

            $DISMOutput = & dism /Online /Cleanup-Image /CheckHealth 2>&1
            $DISMString = ($DISMOutput | Out-String) -replace "`0", ""

            if (
                $DISMString -match "No component store corruption detected" -or
                $DISMString -match "aucune corruption" -or
                $DISMString -match "n'a pas été détectée" -or
                $DISMString -match "n'a été détecté" -or
                $DISMString -match "aucun endommagement"
            ) {

                Add-Result "System Integrity" "DISM CheckHealth" "Image healthy" "OK"
            }
            elseif (
                $DISMString -match "not repairable" -or
                $DISMString -match "non réparable"
            ) {

                Add-Result "System Integrity" "DISM CheckHealth" "Non-repairable corruption" "ERROR"
            }
            elseif (
                $DISMString -match "repairable" -or
                $DISMString -match "réparable"
            ) {

                Add-Result "System Integrity" "DISM CheckHealth" "Repairable corruption detected" "WARNING"
            }
            else {

                Add-Result "System Integrity" "DISM CheckHealth" "Indeterminate result" "INFO"
            }
        }
        catch {

            Add-Result "System Integrity" "DISM CheckHealth" "Could not be run" "INFO"
        }
    }
}
else {

    Add-Result "System Integrity" "DISM CheckHealth" "Skipped (-SkipSlowChecks)" "INFO"
}

#endregion

#region BOOT LOG

# [NEW 18] Detection of recent boot failures in the Kernel-Boot log
Show-Step "Analyzing boot log..." 89

try {

    $BootErrors = Get-WinEvent -FilterHashtable @{
        LogName   = "System"
        ProviderName = "Microsoft-Windows-Kernel-Boot"
        Level     = 2  # Error
        StartTime = (Get-Date).AddDays(-7)
    } -ErrorAction Stop

    if ($BootErrors -and $BootErrors.Count -gt 0) {

        # [FIX v5.2] A plain counter ("21 error(s)") isn't usable for diagnosis - a breakdown by
        # Event ID is added to point directly to the likely cause, in the same spirit as the
        # MessagePattern filtering in Analyze-WindowsLogs.
        $TopIds = $BootErrors | Group-Object Id | Sort-Object Count -Descending | Select-Object -First 3
        $TopIdsStr = ($TopIds | ForEach-Object { "ID $($_.Name) x$($_.Count)" }) -join ", "

        # [FIX v5.4] ID 124 (Kernel-Boot) signals a VBS phase verification failure at startup.
        # Confirmed by cross-diagnosis with msinfo32 on this hardware: "PCR 7 Configuration:
        # Binding not possible" + Kernel DMA Protection disabled -> the OEM firmware
        # (pre-Windows 11, 2019 GL753VD) does not support the measured boot required to seal VBS
        # to PCR7. VBS still runs in degraded mode, hence the event repeating on every boot. Known
        # and accepted hardware limitation (same logic as the structural BitLocker FAIL in
        # Check-Security_Win11): the WARNING is kept visible but the cause is documented directly
        # in the report to avoid re-diagnosing it on every run.
        if ($TopIds | Where-Object { $_.Name -eq 124 }) {
            $TopIdsStr += " [ID 124 = VBS phase verification failure, likely PCR7/pre-Win11 OEM firmware limitation, see msinfo32 'PCR 7 Configuration']"
        }

        Add-Result "Boot Log" "Kernel-Boot errors (last 7 days)" "$($BootErrors.Count) error(s) - $TopIdsStr" "WARNING"
    }
    else {

        Add-Result "Boot Log" "Kernel-Boot errors (last 7 days)" "None" "OK"
    }
}
catch [System.Exception] {

    # No events found (normal case) or provider missing
    Add-Result "Boot Log" "Kernel-Boot errors (last 7 days)" "None (or log not available)" "OK"
}

try {

    # Code 41 (Kernel-Power) = unplanned reboot / abrupt power loss, often correlated with boot issues
    $UncleanShutdowns = Get-WinEvent -FilterHashtable @{
        LogName   = "System"
        ProviderName = "Microsoft-Windows-Kernel-Power"
        Id        = 41
        StartTime = (Get-Date).AddDays(-30)
    } -ErrorAction Stop

    if ($UncleanShutdowns -and $UncleanShutdowns.Count -gt 0) {

        Add-Result "Boot Log" "Unplanned shutdowns (last 30 days)" "$($UncleanShutdowns.Count) event(s) (Event ID 41)" "WARNING"
    }
    else {

        Add-Result "Boot Log" "Unplanned shutdowns (last 30 days)" "None" "OK"
    }
}
catch [System.Exception] {

    Add-Result "Boot Log" "Unplanned shutdowns (last 30 days)" "None (or log not available)" "OK"
}

#endregion

#region BOOT ORDER

Show-Step "Analyzing boot order..." 90

if ($FirmwareType -eq "UEFI") {

    try {

        $BootFirmware = bcdedit /enum firmware 2>&1

        if ($LASTEXITCODE -eq 0) {

            Add-Result "Boot Order" "Firmware boot order" "Accessible" "OK"
        }
        else {

            Add-Result "Boot Order" "Firmware boot order" "Not accessible" "INFO"
        }
    }
    catch {

        Add-Result "Boot Order" "Boot order analysis" "Read error" "INFO"
    }
}

#endregion

#region DUAL BOOT

Show-Step "Analyzing Dual Boot..." 92

try {

    $LinuxDetected = $false

    # [NEW 24] Reuses $BCDEntries computed once in the BCD region
    if (
        $BCDEntries -match "shimx64\.efi" -or
        $BCDEntries -match "grubx64\.efi" -or
        $BCDEntries -match "\\EFI\\ubuntu" -or
        $BCDEntries -match "\\EFI\\debian" -or
        $BCDEntries -match "\\EFI\\fedora" -or
        $BCDEntries -match "\\EFI\\opensuse"
    ) {

        $LinuxDetected = $true
    }

    try {

        $LinuxPartitions = Get-Partition | Where-Object {
            $_.GptType -match "(?i)0FC63DAF"
        }

        if ($LinuxPartitions) {

            $LinuxDetected = $true
        }

    }
    catch {}

    if ($LinuxDetected) {

        Add-Result "Dual Boot" "Linux detected" "Yes" "INFO"
    }
    else {

        Add-Result "Dual Boot" "Linux detected" "No" "OK"
    }
}
catch {

    Add-Result "Dual Boot" "Dual Boot analysis" "Could not be determined" "INFO"
}

#endregion

#region HACKINTOSH

Show-Step "Analyzing OpenCore/Clover..." 94

try {

    # [FIX 4] Uses $BCDEntries (defined in BCD, computed once)
    # $BCDEntries is also initialized to $null in INITIALIZATION as a safety net
    if ($BCDEntries -and (
        $BCDEntries -match "OpenCore" -or
        $BCDEntries -match "Clover"
    )) {

        Add-Result "Hackintosh" "Alternative bootloader" "Detected" "INFO"
    }
    else {

        Add-Result "Hackintosh" "Alternative bootloader" "Not detected" "OK"
    }
}
catch {

    Add-Result "Hackintosh" "Hackintosh analysis" "Could not be determined" "INFO"
}

#endregion

#region WINDOWS 11 COMPATIBILITY

Show-Step "Checking Windows 11 compatibility..." 97

try {

    # [FIX 1] $PartitionStyle guaranteed non-$null thanks to the initialization in INITIALIZATION
    if (
        $FirmwareType -eq "UEFI" -and
        $PartitionStyle -eq "GPT"
    ) {

        Add-Result "Win11 Compatibility" "Boot configuration" "Compliant with Microsoft" "OK"
    }
    else {

        Add-Result `
            "Win11 Compatibility" `
            "Boot configuration" `
            "Not compliant with Microsoft but potentially functional" `
            "INFO"
    }
}
catch {

    Add-Result "Win11 Compatibility" "Compatibility analysis" "Could not be determined" "INFO"
}

#endregion

#region SCORE

Show-Step "Computing health score..." 99

$HealthScore = [Math]::Max(0, $HealthScore)

foreach ($Cat in @($CategoryScores.Keys)) {
    $CategoryScores[$Cat] = [Math]::Max(0, $CategoryScores[$Cat])
}

if ($HealthScore -ge 90) {

    $HealthState      = "EXCELLENT"
    $HealthColor      = "Green"
}
elseif ($HealthScore -ge 75) {

    $HealthState      = "GOOD"
    $HealthColor      = "Yellow"
}
elseif ($HealthScore -ge 50) {

    $HealthState      = "FAIR"
    $HealthColor      = "DarkYellow"
}
else {

    $HealthState      = "CRITICAL"
    $HealthColor      = "Red"
}

Add-Result "Summary" "Boot health score" "$HealthScore / 100" $HealthState

# [NEW 13] Only shows the categories actually impacted by this run
$RelevantCategories = ($Results | Select-Object -ExpandProperty Categorie -Unique) | Where-Object { $CategoryScores.ContainsKey($_) }

foreach ($Cat in $RelevantCategories) {
    Add-Result "Summary" "Score - $Cat" "$($CategoryScores[$Cat]) / 100" "INFO"
}

#endregion

#region BASELINE

# [NEW 15] Saves the baseline for comparison on the next run
try {

    $History = @()

    if (Test-Path $BaselinePath) {

        $PrevBaseline = Get-Content $BaselinePath -Raw -ErrorAction Stop | ConvertFrom-Json

        if ($PrevBaseline.PSObject.Properties.Name -contains "ScoreHistory") {
            $History = @($PrevBaseline.ScoreHistory)
        }
    }

    $History += [PSCustomObject]@{
        Date  = (Get-Date -Format "yyyy-MM-dd HH:mm")
        Score = $HealthScore
    }

    # Keeps the last 20 runs
    if ($History.Count -gt 20) {
        $History = $History[-20..-1]
    }

    $NewBaseline = [PSCustomObject]@{
        WinloadHash  = $WinloadHash
        BootmgfwHash = $BootmgfwHash
        DBXSize      = $DBXCount
        LastScore    = $HealthScore
        LastRun      = (Get-Date -Format "yyyy-MM-dd HH:mm")
        ScoreHistory = $History
    }

    $NewBaseline | ConvertTo-Json -Depth 5 | Out-File $BaselinePath -Encoding UTF8
}
catch {}

#endregion

#region DISPLAY

Show-Step "Finalizing..." 100

# [NEW v6.1] Check-Security-style console: every check was already printed live (framed section
# banner + colored line) as it ran via Add-Result/Show-SectionBanner/Show-CheckLine, so this
# region no longer clears the screen or re-dumps a raw results table - it only prints the closing
# "SUMMARY" box, mirroring Check-Security's own summary block.
if (-not $Silent) {

    $NbOkTotal   = @($Results | Where-Object { $_.Statut -eq "OK" }).Count
    $NbWarnTotal = @($Results | Where-Object { $_.Statut -eq "WARNING" }).Count
    $NbErrTotal  = @($Results | Where-Object { $_.Statut -eq "ERROR" }).Count
    $NbInfoTotal = @($Results | Where-Object { $_.Statut -eq "INFO" }).Count

    $SummaryTitle = "SUMMARY"
    $SInner = $SummaryTitle.Length + 2

    Write-Host ""
    Write-Host ("┌" + ("─" * $SInner) + "┐") -ForegroundColor Cyan
    Write-Host ("│ $SummaryTitle │") -ForegroundColor Cyan
    Write-Host ("└" + ("─" * $SInner) + "┘") -ForegroundColor Cyan
    Write-Host ""

    $Time = Get-Date -Format "HH:mm:ss"

    Write-Host "$Time  " -NoNewline -ForegroundColor DarkGray
    Write-Host "·  " -NoNewline -ForegroundColor Gray
    Write-Host "Total checks: $($Results.Count) | OK: $NbOkTotal | WARN: $NbWarnTotal | FAIL: $NbErrTotal | INFO: $NbInfoTotal"

    Write-Host "$Time  " -NoNewline -ForegroundColor DarkGray
    Write-Host "✓  " -NoNewline -ForegroundColor Green
    Write-Host "Estimated boot health score (weighted by category): " -NoNewline
    Write-Host "$HealthScore / 100" -ForegroundColor $HealthColor

    if (@($History).Count -ge 2) {

        $PrevScore  = [int]$History[-2].Score
        $PrevDate   = $History[-2].Date
        $ScoreDelta = [int]$History[-1].Score - $PrevScore
        $DeltaStr   = if ($ScoreDelta -gt 0) { "+$ScoreDelta" } else { "$ScoreDelta" }
        $DeltaColor = if ($ScoreDelta -gt 0) { "Green" } elseif ($ScoreDelta -lt 0) { "Red" } else { "Gray" }

        Write-Host "$Time  " -NoNewline -ForegroundColor DarkGray
        Write-Host "✓  " -NoNewline -ForegroundColor Green
        Write-Host "Score evolution since the last run ($PrevDate): " -NoNewline
        Write-Host "$PrevScore -> $HealthScore ($DeltaStr)" -ForegroundColor $DeltaColor
    }

    Write-Host "$Time  " -NoNewline -ForegroundColor DarkGray
    Write-Host "·  " -NoNewline -ForegroundColor Gray
    Write-Host "Generating CSV / JSON / HTML reports..."
    Write-Host ""
}

#endregion

#region CSV EXPORT

try {

    $Results | Export-Csv `
        -Path $CsvPath `
        -NoTypeInformation `
        -Encoding UTF8
}
catch {}

#endregion

#region JSON EXPORT

# [NEW 9] JSON export for reuse in other tools or monitoring scripts
try {

    $Results | ConvertTo-Json -Depth 3 | Out-File $JsonPath -Encoding UTF8
}
catch {}

#endregion

#region HTML EXPORT

# [NEW v6.0] HTML report rebuilt on Check-Security_Win11's visual template (dark navy banner with
# the Windows logo and a cyan/purple radial glow, same glow extended across the whole page
# background, same stat-card/table/badge component set) for suite-wide visual consistency.
# The v5.6 per-category tile grid is replaced by an inline "Score by category" table (progress
# bar in the row itself), matching Check-Security's own category table — easier to scan than a
# grid of boxes, and consistent with the rest of the suite.
try {

Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

function Enc { param($T) return [System.Web.HttpUtility]::HtmlEncode([string]$T) }

$HtmlDate     = Get-Date -Format "dd MMM yyyy HH:mm"
$ComputerName = $env:COMPUTERNAME
$WinVersionSafe = if ($WinVersion) { $WinVersion } else { "Unknown" }
$FirmwareTypeSafe = if ($FirmwareType) { $FirmwareType } else { "Unknown" }

# --- Overall score color (same 4-tier scale as the console/JSON state) ---
$ScoreColor = if ($HealthScore -ge 90) { "#a8ce81" } elseif ($HealthScore -ge 75) { "#ffb347" } elseif ($HealthScore -ge 50) { "#fb923c" } else { "#ef7066" }

# --- Trend vs previous run (from the baseline history merged in the BASELINE region) ---
$TrendLine = ""
if (@($History).Count -ge 2) {
    $ScoreDelta = [int]$History[-1].Score - [int]$History[-2].Score
    if ($ScoreDelta -lt 0) {
        $TrendLine = "<span class='trend-down'>&#9660; $ScoreDelta pts vs previous run</span>"
    } elseif ($ScoreDelta -gt 0) {
        $TrendLine = "<span class='trend-up'>&#9650; +$ScoreDelta pts vs previous run</span>"
    } else {
        $TrendLine = "<span class='trend-flat'>&#9644; stable vs previous run</span>"
    }
}

# --- Quick links to critical (ERROR) findings, Check-Security style ---
$CriticalFindings = @($Results | Where-Object { $_.Statut -eq "ERROR" })
$FailLinksHtml = ""
if ($CriticalFindings.Count -gt 0) {
    $i = 0
    foreach ($F in $CriticalFindings) {
        $i++
        $FailLinksHtml += "<a href=`"#boot-fail-$i`" class=`"fail-link`">$(Enc $F.Categorie) — $(Enc $F.Element)</a>"
    }
    $FailLinksBlock = @"
  <p class="section-title">Direct access to critical checks ($($CriticalFindings.Count))</p>
  <div class="fail-links" style="margin-bottom:32px">
    $FailLinksHtml
  </div>
"@
} else {
    $FailLinksBlock = ""
}

# --- Check summary (stat cards) ---
$NbOkTotal    = @($Results | Where-Object { $_.Statut -eq "OK" }).Count
$NbWarnTotal  = @($Results | Where-Object { $_.Statut -eq "WARNING" }).Count
$NbErrTotal   = @($Results | Where-Object { $_.Statut -eq "ERROR" }).Count
$NbInfoTotal  = @($Results | Where-Object { $_.Statut -eq "INFO" }).Count

# --- Score by category (inline table, replaces the v5.6 tile grid) ---
$CategoryOrder = @(
    "System", "Firmware", "Disk", "BCD", "Secure Boot", "TPM", "EFI", "Legacy BIOS",
    "Secure Boot Keys", "Security", "Boot Drivers", "Fast Boot", "BitLocker", "WinRE",
    "Recovery", "SMART", "System Integrity", "Boot Order", "Dual Boot", "Hackintosh",
    "Win11 Compatibility", "Boot Log"
)
$DisplayCategories = @($CategoryOrder | Where-Object {
    $Cat = $_
    $CategoryScores.ContainsKey($Cat) -and (@($Results | Where-Object { $_.Categorie -eq $Cat }).Count -gt 0)
})

$CategoryRows = ""
foreach ($Cat in $DisplayCategories) {

    $CatResults = @($Results | Where-Object { $_.Categorie -eq $Cat })
    $CatScore   = $CategoryScores[$Cat]
    $Weight     = $CategoryWeights[$Cat]
    $BarColor   = if ($CatScore -ge 90) { "#27ae60" } elseif ($CatScore -ge 75) { "#ffb347" } elseif ($CatScore -ge 50) { "#fb923c" } else { "#e74c3c" }

    $CategoryRows += @"
      <tr>
        <td class="cat-cell" style="white-space:nowrap">$(Enc $Cat)</td>
        <td>
          <div style="display:flex;align-items:center;gap:8px">
            <div style="flex:1;background:var(--surface2);border-radius:4px;height:10px;overflow:hidden">
              <div style="width:$CatScore%;height:100%;background:$BarColor;border-radius:4px"></div>
            </div>
            <span style="color:$BarColor;font-weight:700;width:40px;text-align:right">$CatScore%</span>
          </div>
        </td>
        <td style="color:var(--muted);text-align:center">$Weight</td>
        <td style="color:var(--muted);text-align:center">$($CatResults.Count)</td>
      </tr>
"@
}

# --- Detailed results table: category grouped via rowspan, like Check-Security ---
$AllRows = ""
$FailCounter = 0
$i = 0
$Total = $Results.Count
while ($i -lt $Total) {

    $Cat = $Results[$i].Categorie
    $j = $i
    while ($j -lt $Total -and $Results[$j].Categorie -eq $Cat) { $j++ }
    $GroupSize = $j - $i

    for ($k = $i; $k -lt $j; $k++) {

        $Row = $Results[$k]

        $StatusClass = switch ($Row.Statut) {
            "ERROR"   { "fail" }
            "WARNING" { "warn" }
            "OK"      { "ok" }
            default   { "info" }
        }
        $RowClass = switch ($Row.Statut) {
            "ERROR"   { "row-fail" }
            "WARNING" { "row-warn" }
            "OK"      { "row-ok" }
            default   { "" }
        }
        $StatusIcon = switch ($Row.Statut) {
            "ERROR"   { "&#10008;" }
            "WARNING" { "&#9888;" }
            "OK"      { "&#10004;" }
            default   { "&#8505;" }
        }

        $RowId = ""
        if ($Row.Statut -eq "ERROR") {
            $FailCounter++
            $RowId = "boot-fail-$FailCounter"
        }

        $SearchText = "$($Row.Categorie) $($Row.Element) $($Row.Valeur) $($Row.Statut)".ToLower()

        $AllRows += "<tr class=`"$RowClass`" id=`"$RowId`" data-status=`"$($Row.Statut)`" data-search=`"$(Enc $SearchText)`">`n"
        if ($k -eq $i) {
            $AllRows += "  <td class='cat-cell' rowspan='$GroupSize'>$(Enc $Cat)</td>`n"
        }
        $AllRows += "  <td>$(Enc $Row.Element)</td>`n"
        $AllRows += "  <td>$(Enc $Row.Valeur)</td>`n"
        $AllRows += "  <td><span class=`"badge $StatusClass`">$StatusIcon $(Enc $Row.Statut)</span></td>`n"
        $AllRows += "</tr>`n"
    }

    $i = $j
}
if ($Results.Count -eq 0) {
    $AllRows = "<tr><td colspan='4' style='text-align:center;color:var(--muted);padding:20px'>No results.</td></tr>"
}

# --- Windows logo (same artwork/palette as Check-Security's banner) ---
$WinLogoSvg = @'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="9.39 8.477 484.197 428.149" style="width:76px;height:76px;margin-left:24px;align-self:flex-end;filter:drop-shadow(0 0 12px rgba(0,212,255,.4));flex-shrink:0"><path d="m347.015 235.334 42.877-112.525 67.515 25.727-42.877 112.524z" fill="#a8ce81"/><path d="m303.267 350.143 42.92-112.634 67.514 25.726-42.919 112.634z" fill="#fddb1d"/><path d="m263.921 207.033 42.879-112.525 67.406 25.685-42.877 112.525z" fill="#ef7066"/><path d="m220.505 320.972 42.588-111.764 67.406 25.685-42.588 111.764z" fill="#6eaed7"/><path d="m415.69 247.559c-12.962-10.418-30.606-21.623-53.002-30.158-1.455-.43-2.827-1.077-4.131-1.574l33.307-87.41c1.755.295 3.277.875 4.893 1.864 22.194 8.083 39.661 19.097 52.64 29.147zm-44.284 116.221a216.14 216.14 0 0 0 -53.045-30.048c-1.496-.321-2.91-.86-4.131-1.574l34.136-89.586c1.673.513 3.236.984 4.893 1.865 22.153 8.192 39.62 19.206 52.392 29.8zm122.181-212.166s-25.485-37.351-81.827-59.07c-56.66-21.216-98.7-15.447-98.482-15.364l-15.038 39.466c-.135-.3 27.632-5.533 68.583 3.971l-33.597 88.172c-41.045-9.913-68.776-3.795-68.693-4.013l-10.29 27.33s27.736-7.111 69.123 2.558l-34.717 91.108c-33.74-8.499-58.772-7.828-67.506-6.798l-14.5 38.052c10.873-1.087 47.89-2.17 95.075 15.809 56.467 21.392 82.284 57.873 82.408 57.547zm-241.467-32.87 14.747-38.705 41.45-2.259-14.748 38.705zm-91.514 240.162 14.748-38.704 41.45-2.259-14.5 38.052zm16.364-42.944 13.38-35.117 41.492-2.367-13.423 35.225zm60.11-157.752 13.382-35.118 41.45-2.259-13.381 35.117zm-30.034 78.821 13.381-35.116 41.45-2.26-13.381 35.117zm-15.038 39.466 13.38-35.117 41.45-2.26-13.38 35.117zm30.035-78.823 13.422-35.225 41.45-2.259-13.423 35.225zm-10.213-90.174 11.476-30.115 40.145-2.756-11.766 30.876zm-110.927-84.974 4.93-12.937 16.36-1.112-4.93 12.937zm76.852 67.881 8.99-23.592 35.117-2.306-9.03 23.7zm-28.691-20.768 6.835-17.94 28.455-1.483-6.836 17.94zm-24.068-24.734 5.469-14.351 23.495-.884-5.179 13.59zm40.932 183.057 11.476-30.115 39.855-1.995-11.475 30.115zm-110.927-84.974 4.93-12.938 16.36-1.111-5.178 13.59zm76.852 67.881 9.031-23.7 35.077-2.198-9.032 23.7zm-28.691-20.769 6.835-17.938 28.455-1.484-6.835 17.939zm-24.067-24.734 5.22-13.698 23.743-1.536-5.179 13.59zm41.222 182.297 11.475-30.115 40.145-2.757-11.475 30.116zm-110.927-84.974 5.178-13.59 16.112-.46-4.93 12.938zm77.1 67.229 8.74-22.94 35.119-2.307-8.783 23.05zm-28.691-20.769 6.587-17.287 28.454-1.483-6.587 17.286zm-24.026-24.843 5.178-13.59 23.495-.883-5.178 13.59z" fill="#000101"/><path d="m114.017 84.174 4.889-12.83 17.411-1.582-4.888 12.829zm88.133 61.472 9.529-25.006 32.364-1.612-9.28 24.353zm-34.836-17.383 7.913-20.766 29.355-1.887-7.913 20.766zm-29.271-19.247 6.049-15.873 22.733-1.173-6.007 15.764zm-50.589-48.909 4.102-10.763 12.995-.776-4.101 10.764zm11.525 63.532 4.93-12.938 17.411-1.583-4.93 12.938zm88.133 61.472 9.57-25.114 32.612-2.265-9.528 25.006zm-34.588-18.035 7.664-20.113 29.397-1.996-7.954 20.874zm-29.478-18.703 6.007-15.764 22.734-1.174-5.758 15.112zm-50.63-48.8 4.392-11.525 12.995-.775-4.392 11.524z" fill="#ef7066"/><path d="m68.115 204.635 4.93-12.937 17.122-.822-4.93 12.938zm87.844 62.234 9.57-25.114 32.653-2.374-9.57 25.114zm-34.547-18.144 7.913-20.766 29.107-1.235-7.664 20.113zm-29.229-19.355 5.717-15.004 22.733-1.173-5.717 15.003zm-50.92-48.04 4.391-11.524 12.995-.776-4.35 11.416zm11.814 62.77 4.93-12.937 17.122-.822-4.93 12.938zm88.133 61.473 9.28-24.353 32.654-2.374-9.57 25.115zm-34.836-17.383 7.913-20.765 29.397-1.996-7.955 20.874zm-29.229-19.355 5.717-15.004 23.023-1.934-6.007 15.764zm-50.631-48.801 4.102-10.763 12.995-.775-4.101 10.763z" fill="#6eaed7"/></svg>
'@

$Html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Check-Boot v6.0 — $(Enc $ComputerName)</title>
<style>
  :root {
    --bg: #080b12; --surface: #111827; --surface2: #1a2235;
    --border: #1e2d45; --text: #e2e8f0; --muted: #94a3b8;
    --ok: #a8ce81; --warn: #ffb347; --fail: #ef7066; --info: #7c6af7;
    --accent: #00d4ff; --accent2: #0099cc; --accent3: #005f80;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html { background: var(--bg); }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; line-height: 1.5; position: relative; }
  body::before {
    content:''; position: fixed; inset: 0;
    background:
      radial-gradient(ellipse at 15% 0%, rgba(0,212,255,.07) 0%, transparent 55%),
      radial-gradient(ellipse at 85% 10%, rgba(124,106,247,.06) 0%, transparent 50%),
      radial-gradient(ellipse at 50% 100%, rgba(0,153,204,.05) 0%, transparent 55%);
    pointer-events: none; z-index: 0;
  }
  header, .container, footer { position: relative; z-index: 1; }

  header { background: linear-gradient(160deg,#060c1a 0%,#0a1628 50%,#060a14 100%); border-bottom: 2px solid var(--accent3); padding: 32px 40px 24px; position: relative; overflow: hidden; }
  header::before { content:''; position:absolute; top:0; left:0; right:0; bottom:0; background: radial-gradient(ellipse at 20% 50%,rgba(0,212,255,.06) 0%,transparent 60%), radial-gradient(ellipse at 80% 20%,rgba(124,106,247,.05) 0%,transparent 50%); pointer-events:none; }
  .titlerow { display:flex; align-items:flex-end; gap:0; position:relative; z-index:1; }
  .title-text h1 { font-family:'Cascadia Code','Consolas','Courier New',monospace; font-size:26px; font-weight:700; color:var(--accent); text-shadow:0 0 20px rgba(0,212,255,.4); letter-spacing:1px; margin:0 0 10px 0; }
  .logo-sub { font-family:'Cascadia Code','Consolas',monospace; font-size:12px; color:var(--muted); letter-spacing:2px; margin-bottom:14px; }
  .logo-sub b { color:var(--accent); }
  .meta-bar { display:flex; flex-wrap:wrap; gap:8px 24px; font-size:11.5px; color:#475569; border-top:1px solid var(--border); padding-top:12px; margin-top:4px; position:relative; z-index:1; }
  .meta-bar span { display:flex; align-items:center; gap:6px; }
  .meta-bar b { color:var(--muted); }
  .meta-dot { width:5px; height:5px; border-radius:50%; background:var(--accent); display:inline-block; box-shadow:0 0 6px var(--accent); }

  .container { max-width: 1400px; margin: 0 auto; padding: 32px 40px; }

  .summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; margin-bottom: 32px; }
  .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 20px; text-align: center; }
  .stat-card .num { font-size: 36px; font-weight: 800; line-height: 1; margin-bottom: 6px; }
  .stat-card .lbl { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
  .stat-card.ok   .num { color: var(--ok);   }
  .stat-card.warn .num { color: var(--warn);  }
  .stat-card.fail .num { color: var(--fail);  }
  .stat-card.info .num { color: var(--info);  }
  .stat-card.score .num { color: #a8ce81; }

  .section-title { font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); margin-bottom: 12px; }

  table { width: 100%; border-collapse: collapse; background: var(--surface); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; margin-bottom: 32px; }
  thead th { background: var(--surface2); padding: 12px 16px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.8px; color: var(--muted); border-bottom: 1px solid var(--border); }
  tbody td { padding: 10px 16px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tbody tr:last-child td { border-bottom: none; }
  .cat-cell { color: var(--accent); font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; background: var(--surface2); border-right: 1px solid var(--border); vertical-align: top; white-space: nowrap; }
  .row-fail { background: rgba(239,112,102,0.05); }
  .row-warn { background: rgba(255,179,71,0.05); }
  .row-ok   { background: rgba(168,206,129,0.03);  }
  .detail   { color: var(--muted); }

  .badge { display: inline-block; padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; white-space: nowrap; }
  .badge.ok   { background: rgba(168,206,129,0.15);  color: var(--ok);   border: 1px solid rgba(168,206,129,0.3);  }
  .badge.warn { background: rgba(255,179,71,0.15); color: var(--warn); border: 1px solid rgba(255,179,71,0.3); }
  .badge.fail { background: rgba(239,112,102,0.15);  color: var(--fail); border: 1px solid rgba(239,112,102,0.3);  }
  .badge.info { background: rgba(124,106,247,0.15); color: var(--info); border: 1px solid rgba(124,106,247,0.3); }

  .score-bar-wrap { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 24px; margin-bottom: 32px; }
  .score-bar-track { background: var(--surface2); border-radius: 8px; height: 18px; overflow: hidden; margin-top: 10px; }
  .score-bar-fill { height: 100%; border-radius: 8px; transition: width 1s; }
  .score-label { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; flex-wrap: wrap; gap: 8px; }
  .score-label span:first-child { font-weight: 700; font-size: 16px; }
  .score-value { font-size: 22px; font-weight: 800; }

  .fail-links { display: flex; flex-wrap: wrap; gap: 8px; }
  .fail-link { font-size: 12px; padding: 6px 12px; border-radius: 20px; background: rgba(239,112,102,0.12); color: var(--fail); border: 1px solid rgba(239,112,102,0.3); text-decoration: none; white-space: nowrap; }
  .fail-link:hover { background: rgba(239,112,102,0.22); }

  .search-box { width: 100%; max-width: 420px; margin-bottom: 16px; padding: 10px 14px; border-radius: 8px; border: 1px solid var(--border); background: var(--surface); color: var(--text); font-size: 13px; }
  .search-box:focus { outline: none; border-color: var(--accent); }
  .filter-bar { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }
  .filter-chip { font-size: 11px; padding: 5px 12px; border-radius: 20px; border: 1px solid var(--border); background: var(--surface2); color: var(--muted); cursor: pointer; user-select: none; }
  .filter-chip.active { background: var(--accent); color: white; border-color: var(--accent); }
  .no-results { color: var(--muted); font-size: 13px; padding: 16px; text-align: center; display: none; }

  footer { text-align: center; padding: 24px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--border); margin-top: 16px; }
</style>
</head>
<body>
<header>
  <div class="titlerow">
    <div class="title-text">
      <h1>Check-Boot v6.0</h1>
      <div class="logo-sub">by <b>Nephren</b></div>
    </div>
    $WinLogoSvg
  </div>
  <div class="meta-bar">
    <span><span class="meta-dot"></span>Machine: <b>$(Enc $ComputerName)</b></span>
    <span>Date: <b>$HtmlDate</b></span>
    <span>OS: <b>$(Enc $WinVersionSafe)</b></span>
    <span>Firmware: <b>$(Enc $FirmwareTypeSafe)</b></span>
  </div>
</header>
<div class="container">

  <!-- Score -->
  <div class="score-bar-wrap">
    <div class="score-label">
      <span>Boot health score</span>
      <span class="score-value" style="color:$ScoreColor">$HealthScore / 100 — $HealthState</span>
      $TrendLine
    </div>
    <div class="score-bar-track"><div class="score-bar-fill" style="width:$HealthScore%;background:linear-gradient(90deg,$ScoreColor,${ScoreColor}99)"></div></div>
  </div>

$FailLinksBlock

  <!-- Summary -->
  <p class="section-title">Check summary</p>
  <div class="summary-grid">
    <div class="stat-card score"><div class="num">$($Results.Count)</div><div class="lbl">Total checks</div></div>
    <div class="stat-card ok">  <div class="num">$NbOkTotal</div>  <div class="lbl">OK</div></div>
    <div class="stat-card warn"><div class="num">$NbWarnTotal</div><div class="lbl">Warning</div></div>
    <div class="stat-card fail"><div class="num">$NbErrTotal</div><div class="lbl">Critical</div></div>
    <div class="stat-card info"><div class="num">$NbInfoTotal</div><div class="lbl">Info</div></div>
  </div>

  <!-- Score by category (inline, replaces the tile grid) -->
  <p class="section-title">Score by category</p>
  <table style="margin:0 0 32px 0">
    <thead>
      <tr>
        <th>Category</th>
        <th>Partial score</th>
        <th style="text-align:center">Weight</th>
        <th style="text-align:center">Checks</th>
      </tr>
    </thead>
    <tbody>
$CategoryRows
    </tbody>
  </table>

  <!-- Full table -->
  <p class="section-title">Detailed results</p>
  <input type="text" id="searchBox" class="search-box" placeholder="🔎 Search (category, check, value, status)...">
  <div class="filter-bar">
    <span class="filter-chip active" data-filter="ALL">All</span>
    <span class="filter-chip" data-filter="ERROR">Critical</span>
    <span class="filter-chip" data-filter="WARNING">Warning</span>
    <span class="filter-chip" data-filter="OK">OK</span>
    <span class="filter-chip" data-filter="INFO">Info</span>
  </div>
  <table id="resultsTable">
    <thead>
      <tr>
        <th style="width:150px">Category</th>
        <th style="width:280px">Item</th>
        <th>Value</th>
        <th style="width:120px">Status</th>
      </tr>
    </thead>
    <tbody>
$AllRows
    </tbody>
  </table>
  <p class="no-results" id="noResults">No result matches this filter.</p>

</div>
<footer>Report automatically generated by Check-Boot.ps1 v6.0 — $(Enc $ComputerName) — $HtmlDate</footer>
<script>
  (function () {
    var searchBox = document.getElementById('searchBox');
    var chips = document.querySelectorAll('.filter-chip');
    var rows = document.querySelectorAll('#resultsTable tbody tr');
    var noResults = document.getElementById('noResults');
    var activeStatus = 'ALL';

    function applyFilters() {
      var term = (searchBox.value || '').toLowerCase().trim();
      var visibleCount = 0;
      rows.forEach(function (row) {
        var matchesStatus = (activeStatus === 'ALL') || (row.getAttribute('data-status') === activeStatus);
        var matchesSearch = !term || (row.getAttribute('data-search') || '').indexOf(term) !== -1;
        var show = matchesStatus && matchesSearch;
        row.style.display = show ? '' : 'none';
        if (show) visibleCount++;
      });
      noResults.style.display = (visibleCount === 0) ? 'block' : 'none';
    }

    searchBox.addEventListener('input', applyFilters);
    chips.forEach(function (chip) {
      chip.addEventListener('click', function () {
        chips.forEach(function (c) { c.classList.remove('active'); });
        chip.classList.add('active');
        activeStatus = chip.getAttribute('data-filter');
        applyFilters();
      });
    });
  })();
</script>
</body>
</html>
"@

    $Html | Out-File $HtmlPath -Encoding UTF8

}
catch {}

#endregion

#region TOAST

# [NEW 26] Desktop toast notification at the end of the run
try {

    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
    [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null

    $ToastXmlString = @"
<toast>
  <visual>
    <binding template="ToastGeneric">
      <text>Check-Boot - Analysis complete</text>
      <text>Score: $HealthScore / 100 ($HealthState)</text>
    </binding>
  </visual>
</toast>
"@

    $ToastXml = New-Object Windows.Data.Xml.Dom.XmlDocument
    $ToastXml.LoadXml($ToastXmlString)
    $Toast = New-Object Windows.UI.Notifications.ToastNotification($ToastXml)
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Check-Boot").Show($Toast)
}
catch {

    # Silent: non-blocking if the toast API is not available (PS5.1 without WinRT, etc.)
}

#endregion

#region END

# [NEW v6.1] "AUDIT COMPLETE" box, Check-Security style: boxed title, a text score bar, the
# checks breakdown, the trend vs the previous run, then the generated report paths under ">>".
if (-not $Silent) {

    $NbOkTotal   = @($Results | Where-Object { $_.Statut -eq "OK" }).Count
    $NbWarnTotal = @($Results | Where-Object { $_.Statut -eq "WARNING" }).Count
    $NbErrTotal  = @($Results | Where-Object { $_.Statut -eq "ERROR" }).Count

    $DoneTitle = "✓ AUDIT COMPLETE"
    $DInner    = $DoneTitle.Length + 2

    Write-Host ""
    Write-Host ("┌" + ("─" * $DInner) + "┐") -ForegroundColor $HealthColor
    Write-Host ("│ $DoneTitle │") -ForegroundColor $HealthColor
    Write-Host ("└" + ("─" * $DInner) + "┘") -ForegroundColor $HealthColor
    Write-Host ""

    $BarWidth = 30
    $Filled   = [Math]::Round($BarWidth * $HealthScore / 100)
    $Bar      = ("█" * $Filled) + ("░" * ($BarWidth - $Filled))

    Write-Host "  Boot health score   " -NoNewline
    Write-Host $Bar -NoNewline -ForegroundColor $HealthColor
    Write-Host "   $HealthScore/100" -ForegroundColor $HealthColor

    Write-Host "  Checks              " -NoNewline
    Write-Host "$($Results.Count) total · " -NoNewline
    Write-Host "✓ $NbOkTotal OK" -NoNewline -ForegroundColor Green
    Write-Host " · " -NoNewline
    Write-Host "! $NbWarnTotal WARN" -NoNewline -ForegroundColor Yellow
    Write-Host " · " -NoNewline
    Write-Host "X $NbErrTotal FAIL" -ForegroundColor Red

    if (@($History).Count -ge 2) {

        $ScoreDelta = [int]$History[-1].Score - [int]$History[-2].Score
        $DeltaStr   = if ($ScoreDelta -gt 0) { "+$ScoreDelta point(s)" } elseif ($ScoreDelta -lt 0) { "$ScoreDelta point(s)" } else { "no change" }
        $DeltaColor = if ($ScoreDelta -gt 0) { "Green" } elseif ($ScoreDelta -lt 0) { "Red" } else { "Gray" }

        Write-Host "  Evolution           " -NoNewline
        Write-Host "$DeltaStr" -NoNewline -ForegroundColor $DeltaColor
        Write-Host " vs previous run"
    }

    Write-Host ""
    Write-Host "  >> CSV export    " -NoNewline -ForegroundColor DarkGray
    Write-Host $CsvPath
    Write-Host "  >> JSON export   " -NoNewline -ForegroundColor DarkGray
    Write-Host $JsonPath
    Write-Host "  >> HTML report   " -NoNewline -ForegroundColor DarkGray
    Write-Host $HtmlPath
    Write-Host ""
}

if ((Test-Path $HtmlPath) -and -not $Silent) {
    $OuvrirRep = Read-Host "  Open the HTML report in the browser? [Y/n]"
    if ($OuvrirRep -eq '' -or $OuvrirRep -match '^[Yy]') { Start-Process $HtmlPath }
}

if (-not $Silent) {
    Write-Host ""
    Write-Host "  Press ENTER to close this window..." -ForegroundColor DarkGray
    Read-Host
}

# SIG # Begin signature block
# MIIFwgYJKoZIhvcNAQcCoIIFszCCBa8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD7vnki0cSlVl6+
# JsLQYTaPXL4FO9yKDPhr8lMzsEQWyqCCAygwggMkMIICDKADAgECAhB6X4r8AlBU
# p0MV3JpMuQ6sMA0GCSqGSIb3DQEBCwUAMCoxKDAmBgNVBAMMH05lcGhyZW4gUG93
# ZXJTaGVsbCBDb2RlIFNpZ25pbmcwHhcNMjYwNzA0MDIzMzIwWhcNMzEwNzA0MDI0
# MzIwWjAqMSgwJgYDVQQDDB9OZXBocmVuIFBvd2VyU2hlbGwgQ29kZSBTaWduaW5n
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1JnV5AocUnAMNIG3nYF9
# 5mOQz5NzMYJqc9D6mq3pjRlmuYIgvYEuJL5dvt8eoAiUKd+XHTaY5wl+zt7LUon+
# TmEldVwfrYvROpI+5TDyBRc5BzY4uACsA4JUM4ienjX04BBKT3uH6JwHzBluWqcG
# Xrg16NqzDiae7WNzVrev+BME00mgSvBo3hKp3sHIvFQaAmjGXLyJd+llfnBpmoD9
# JnOxMKO7VFIlhAz5cEUnFu/xDLHgARdBUfXA5odScWKiDvygNZsH1vHo07Oo7pDK
# awR3bT6lcXWRXSUmawgE1mZra+b9qpeNol+5J+86zN83RccBKZBUtQQoyy+cv20x
# VQIDAQABo0YwRDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMw
# HQYDVR0OBBYEFNxVaDYoNv8UXQWnbtEy/DTaQHjYMA0GCSqGSIb3DQEBCwUAA4IB
# AQCE4NqZbeximmbNEORyLxvIYiMQwP59B9R95blQQ/zugPSt4wab61yBbgO1E3mH
# mUdN0fCHhN/u0uB7h7ZBYw1w4hnzoiBac4UYzsXH4/D41gBjutbtDllRy6/zs3dl
# /hbbHAmwKXdjNVLG9cPkpWlkvKR1DJLMugU2uj+S6k+U7DfHo76sbAKqiu3biXtd
# mao6PP99EU7JBYZjsJ+BsnYcZ2KcnZ8TKiRuhSXoxAyPman7Z0BVo1H2O+fxd96b
# 4W8VclmpFh7T2CyRAHolwEy5coFYyueisO0PZg+nKwXr66+m1T1CBLQYwh79/SKO
# wGUJyU5RtTryD+hfLwkTQKVCMYIB8DCCAewCAQEwPjAqMSgwJgYDVQQDDB9OZXBo
# cmVuIFBvd2VyU2hlbGwgQ29kZSBTaWduaW5nAhB6X4r8AlBUp0MV3JpMuQ6sMA0G
# CWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZI
# hvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcC
# ARUwLwYJKoZIhvcNAQkEMSIEIA7mZoH9l4C6fQBCiUUUvSGITCNupl8YqwgUxzMd
# WQjoMA0GCSqGSIb3DQEBAQUABIIBAI/Kt+OBlbwXRoYewM6FCKjYShSnr3+EinLP
# CK8xGUQIChvALlSsR81QIzUbbGpdFzJO8HnIY90KrfbKMfv8CBa2GHNsLUrPxnvw
# b13bxC/0G30y2mv6tVEc+iAkRFGu6OU0gYCuZCNlSCdKDe1ghyf8CcwbL6NUkG79
# HeYJmVFJJLQ3KzE2MbsW+XoFwksFZBpUBd5DYBJwX6RgUKEV18CfV0mepCeQSLHr
# CfTZMVQxKwlFqFd5X0FoX/2WZDmnzfUa+hV2i/LZ40oeIUEEFgyQtbmBdp6r/kix
# zmun6yn+yvBCAJeeeQ48Vc78UdSUjO5pFxlj8XNjuG41GElao3Q=
# SIG # End signature block
