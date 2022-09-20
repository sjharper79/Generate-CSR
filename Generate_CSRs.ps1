#region Detailed Help
<#
    .SYNOPSIS
    This PowerShell script is to generate certificate signing requests with corresponding keys in bulk using a comma separated values input file.

    .DESCRIPTION
    Create bulk CSRs and Keys using a CSV file as input. Zip files are created with the maximum of 100 CSRs per zip to enable compatibility with uploading to the DoD NPE-Portal for Bulk Submit.

    You must have OpenSSL installed on your pc and you must have the path to the OpenSSL command in your PATH environment variable.

    You must also have Java installed and have the path to the keytool.exe command in your PATH environment variable.

    You must also have 7-zip installed and have teh path to the 7z.exe command in your PATH environment variable.

    .PARAMETER RootPath
    Mandatory
    The path to the working directory that will be the root of all other files used or created by this script.

    .PARAMETER CSVFile
    Mandatory
    CSVFilePath the CSV file that contains the certificate request details.

    .PARAMETER CSRRootDir
    Mandatory
    CertRootDir is the root directory where all of the files pertaining to this script will be kept. This is a relative path or a full path. 

    .PARAMETER Password
    Optional
    A SecureString password to be used as the private key password
        
    .PARAMETER CreateCSR
    This switch tells the script to create the CSR and Key files. 

    .PARAMETER ZIP
    This switch instructs the script to zip all of the CSR directories into zip files

    .PARAMETER Unzip
    This switch instructs the script to unzip all of the files provided by NPE

    .PARAMETER CreateP12
    This switch instructs the script to create the PKCS12 .P12 files out of the private key and the certificates. Use with -Password to provide a password for the P12 file or the private key.

    .PARAMETER CreateKeyStore
    This switch instructs the script to put all of the P12 files into the Java Keystore file. Use with -P12PW to provide the password for the P12 files and -KSPW to provide the Keystore password.

    .PARAMETER RenameFiles
    This switch instructs the script to rename all of the files provided by NPE to the alias name found in the CSV file.

    .PARAMETER OverwriteCSV
    When specifying a CSV file, if the file exists in the rootdir, it will not be overwritten. Use this switch to force overwriting.

    .PARAMETER P12PW
    The Password for the pkcs12 file

    .PARAMETER KSPW
    The Password for the Java Keystore file

    .EXAMPLE
    PS C:\> CSR-Requests.ps1 -CSVFilePath "C:\users\user1\desktop\certificates.csv"

    .INPUTS
    CSV file formatted with at least the following fields:
    lname
    fname
    mi
    gen
    san
    DODID
    password
    alias

    The lname field is the user's last name.
    The fname field is the user's first name.
    The mi field is the user's middle name.
    The gen field is the generation of the user (egu. I, II, III, Jr. Sr. Etc.).
    The san field is the user's email address and will be the subject alternate name in the RFC822Name format in the resulting Certificate.
    The DODID field is the 10-digit DoD EDIPI or other identifier.
    The password field is the plain-text password that will be used to protect the private key and the resulting pkcs12 file.
    The alias field is used for the Friendly Name field in the java keystore file, and is used to create csr, key, and p12 files.

    .OUTPUTS
    1) CSRs and Keys for each user in the CSV file
    2) ZIP files with up to 100 CSRs each to be uploaded to NPE by an RA
    3) Unzipped NPE response files, which include all of the requested certificates
    4) PKCS12 files containing the certificates with their matching private keys
    5) A java keystore file with all of the PKCS12 files added. 

    .NOTES
    This script was created for Defense Information Systems Agency in response to a request from the US Navy to generate 8,500 certificates for testing purposes.

    This script comes with no warranty or guaranteee of any kind. Use at your own risk. 

    .LINK
    https://github.com/sjharper79/Generate-CSR

#>
#endregion

#region Parameters
 param(
    # All Sets: rootPath, CSVFile
    # Rename: RenameFiles
    # CreateP12: CreateP12, Password, P12PW
    # Keystore: CreateKeyStore, Password, KSPW, P12PW
    # Zip: Zip
    # Unzip: Unzip

    [Parameter(ParameterSetName="CreateCSR", Mandatory, HelpMessage="The top level directory where all scirpt input and output will be stored.")] 
    [Parameter(ParameterSetName="Rename", Mandatory, HelpMessage="The top level directory where all scirpt input and output will be stored.")] 
    [Parameter(ParameterSetName="CreateP12", Mandatory, HelpMessage="The top level directory where all scirpt input and output will be stored.")] 
    [Parameter(ParameterSetName="Zip", Mandatory, HelpMessage="The top level directory where all scirpt input and output will be stored.")] 
    [Parameter(ParameterSetName="Unzip", HelpMessage="The top level directory where all scirpt input and output will be stored.")] 
    [Parameter(ParameterSetName="Keystore", Mandatory, HelpMessage="The top level directory where all scirpt input and output will be stored.")] 
    [String]$rootPath,
    
    [Parameter(ParameterSetName="CreateCSR", Mandatory, HelpMessage="The CSV file to use to perform this script.")] 
    [Parameter(ParameterSetName="Rename", Mandatory, HelpMessage="The CSV file to use to perform this script.")] 
    [Parameter(ParameterSetName="Keystore", Mandatory, HelpMessage="The CSV file to use to perform this script.")] 
    [Parameter(ParameterSetName="Unzip", Mandatory, HelpMessage="The CSV file to use to perform this script.")] 
    [Parameter(ParameterSetName="CreateP12", Mandatory, HelpMessage="The CSV file to use to perform this script.")] 
    [String]$CSVFile,

    [Parameter(ParameterSetName="CreateP12", HelpMessage="Create PKCS12 files from Certs and Keys.")]
    [Switch]$CreateP12,
    
    [Parameter(ParameterSetName="Keystore", HelpMessage="Create the Java Keystore and put all of the PKCS12 files into it.")]
    [Switch]$CreateKeyStore,

    [Parameter(ParameterSetName="CreateCSR", HelpMessage="Create CSR and Keys files.")]
    [Switch]$CreateCSR,
    
    [Parameter(ParameterSetName="Zip", HelpMessage="Zip up 100 files at a time into zip files.")]
    [Switch]$ZIP,

    [Parameter(ParameterSetName="Unzip", HelpMessage="Unzip the files provided by NPE.")]
    [Switch]$Unzip,
    
    [Parameter(ParameterSetName="Rename", HelpMessage="Rename the files from NPE.")]
    [Switch]$RenameFiles,

    [Parameter(HelpMessage="Force overwriting the CSV file if it already exists.")]
    [Switch]$OverwriteCSV,    

    [Parameter(ParameterSetName="Keystore", HelpMessage="The password for the key file.")]
    [Parameter(ParameterSetName="CreateCSR", HelpMessage="The password for the key file.")]
    [Parameter(ParameterSetName="CreateP12", HelpMessage="The password for the key file.")]
    [Switch]$Password,
    
    [Parameter(ParameterSetName="Keystore", HelpMessage="The password for the PKCS12 file.")]
    [Parameter(ParameterSetName="CreateP12", HelpMessage="The password for the PKCS12 file.")]
    [Switch]$P12PW,
    
    [Parameter(ParameterSetName="Keystore", HelpMessage="The password for the Java keystore file.")]
    [Switch]$KSPW,
    
    [Parameter(ParameterSetName="Unzip", HelpMessage="The path to the downloaded zip files from NPE.")]
    [String]$NPECertDownloadsDir  
    
    
)
#endregion Parameters

#region Set up variables
#outputFolderPath is the path where files are created (including subdirs)
$outputFolderPath = "$rootPath\output"
#CSVFilePath is the full path to the CSVFile in the rootPath
$CSVFilePath = "$rootPath\$(split-path $CSVFile -leaf)"
#csrExportPath is the directory where the CSR files and subdirectories are created.
$csrExportPath = "$outputFolderPath\CSRs"
#keyExportPath is the directory to hold all of the generated key files.
$keyExportPath = "$outputFolderPath\Keys"
#condifFilePath is the path to the openssl.cfg file that this script repeatedly creates
$configFilePath = "$rootPath\openssl.cfg"
#keyExportPath is the directory to hold all of the generated key files.
$zipExportPath = "$outputFolderPath\Zips"
#certExportPath is the directory where the CER files will be stored.
$certExportPath = "$outputFolderPath\CERs"
#p12ExportPath is the directory where the PKCS12 files will be stored.
$p12ExportPath = "$outputFolderPath\P12s"
#destKeyStore is the Java keystore
$destKeyStore = "$outputFolderPath\keystore.jks"
#endregion Set up variables

#region Functions

#region Function Write-Config
function Write-Config ($string){     <#
        .SYNOPSIS 
        Write the line of text to the openssl config file
        .DESCRIPTION
        The config file is stored in the $configFilePath variable and the $string variable, input to this function, will be written to the config file.
        .INPUTS
        $string is a string literal or a string variable that contains the line of text to add to the config file
        .OUTPUTS
        The function will add the line of text to the config file
        .EXAMPLE
        Write-Config "Hello World"
    #>

    write-output $string | Out-File $configFilePath -Append -Encoding utf8
}
#endregion Function Write-Config

#region Function Initialize-MissingDirectory
function Initialize-MissingDirectory ($dir){

    <#
        .SYNOPSIS 
        Create the missing directories.
        .DESCRIPTION
        Will create any directory named $dir if it doesn't exist. 
        .INPUTS
        $dir is a string litteral refering to a directory, or a string variable containing a directory name
        .OUTPUTS
        The function will create the directory
        .EXAMPLE
        Initialize-MissingDirectory "c:\users\user\Desktop\HelloWorld"
        .EXAMPLE
        Initialize-MissingDirectory $adir
    #>
   
    # if the outputFolderPath doesn't exist, make it
    if ( -not $(test-path $dir) ) {
        write-host "Creating $dir"
        New-Item -Path $dir -ItemType Directory
    }
    else {
        write-host "$dir already exists"
    }
}
#endregion Function Initialize-MissingDirectory

#region Function Update-Field
function Update-Field ($certField){
    <#
        .SYNOPSIS 
        Add . to a field if the field is not empty (used for creating proper SANs in certificates)
        .DESCRIPTION
        This function will ensure that the generation has a period (.) in it if the generation is not empty.
        .INPUTS
        $certField is a string value
        .OUTPUTS
        The sting value with a prepended period (.), or null
        .EXAMPLE
        $anArray.field1 = Update-Field $anArray.field1
    #>

    if ( $certField -ne '' )
    {
        return '.' + $certField
    }
    else {
        return $certField
    }
}
#endregion Function Update-Field

#region Function Read-CSV
function Read-CSV () {    <#
        .SYNOPSIS
        Read the CSV file into an array
        .DESCRIPTION
        The CSV file contains all of the user certificates to create. Read them into an array. The CSV file must have headers.
        .INPUTS
        $csvpath is the path to the CSV file
        .OUTPUTS
        returns a two-dimensional array containing all of the content of the CSV file
        .EXAMPLE
        $certRequestList = Read-CSV $CSVFilePath
    #>    
    # Import the csv file into an array
    $certrequests = Import-CSV $CSVFilePath 
    return $certrequests
}
#endregion Function Read-CSV

#region Function Invoke-OpenSSL
function Invoke-OpenSSL ($configFilePath, $keyfile, $csrfile, $PW) {
    <#
        .SYNOPSIS
        Run OpenSSL to create the CSR and Key file
        .DESCRIPTION
        Pass in the configFilePath, the keyFile, and csrFile variables.
        .INPUTS
        $configFilePath is the path to the OpenSSL config file generated for this certificate request
        $keyFile is the fully qualified path to the keyfile that OpenSSL will generate
        $csrFile is the fully qualified path to the CSR file that OpenSSL will generate

        .OUTPUTS
        A CSR file and a KEY file in the locations specified will be created by OpenSSL.

        .EXAMPLE
        Invoke-OpenSSL $configFile $keyFile $csrFile
    #>
    #$ErrorActionPreference = "SilentlyContinue"
    if (defaultPassword $clearPass){
        & openssl req -new -config $configFilePath -newkey rsa:2048 -keyout $keyfile -out $csrfile
    }
    else {
        & openssl req -new -config $configFilePath -newkey rsa:2048 -keyout $keyfile -out $csrfile -passout pass:$PW
    }
}
#endregion Function Invoke-OpenSSL

#region Function Invoke-Zip
function Invoke-Zip ($ZipFileName, $ZipDir){
        <#
        .SYNOPSIS
        Zip up the files in batches of 100 to submit in bulk to NPE
        .DESCRIPTION
        NPE can accept ZIP files with up to 100 CSRs in it for the bulk submission function. This function will create a zip file with up to 100 CSRs in it
        .INPUTS
        $ZipFileName is the name of the Zip file you want the function to create
        $ZipDir is the directory you want to ZIP
        .OUTPUTS
        Creates a ZIP file called $ZipFileName with the contents of $ZipDir (up to 100 CSR files only)
        .EXAMPLE
        Invoke-Zip $ZipFileName $ZipDir
    #>
    & 'C:\Program Files\7-Zip\7z.exe' a $ZipFileName "$dir\*"
}
#endregion Function Invoke-Zip

#region Function Invoke-Unzip
function Invoke-Unzip ($ZipFileName, $ZipDir){

    <#
        .SYNOPSIS
        Unzip the certificate files returned by NPE
        .DESCRIPTION
        NPE returns Certificates in Zip files when using Submit Bulk. This function will unzip them. This is useful when receiving a lot of zip files.
        .INPUTS
        $ZipFileName is the file you want to unzip
        $ZipDir is the directory to which you want to unzip the file
        .OUTPUTS
        The contents of the zip file unziped into the directory of your choice.
        .EXAMPLE
        Invoke-Unzip $ZipFileName $ZipDir
    #>
    & 'C:\Program Files\7-Zip\7z.exe' e $ZipFileName -o"$ZipDir"
}
#endregion Function Invoke-Unzip

#region Function Rename-Certificate
function Rename-Certificates ($certreqs) {    <#
        .SYNOPSIS
        Rename the CER files that NPE returned
        .DESCRIPTION
        NPE returns CER files named to match the CN of the certifcate. This can be a very long filename and can be renamed to match a shorter name. The CSV file has an alias field. 
        You could used the alias field as a potential new name for the cert file.
        .OUTPUTS
        All certs in the Cert directory will be renamed
    #>
    
    foreach ($cert in $certreqs){
        $oldName = $cert.fname +'.' + $cert.lname +'.' + $cert.mi + $cert.gen +'.' + $cert.dodid + ".cer"
        write-host $oldName
        write-host "$certExportPath\$newname"
        $newName = $cert.alias + ".cer"
        Rename-Item -LiteralPath "$certExportPath\$oldName" -NewName "$certExportPath\$newName"
    }
}
#endregion Function Rename-Certificates

#region Function Iniitialize-P12
function Initialize-P12 {
    <#
        .SYNOPSIS
        This function will create p12 (pkcs12) files from the certs and keys.
        .DESCRIPTION
        PKCS12 files contain both the certificate and corresponding private key. The files can be protected with a password and can have an alias (friendly name) assigned to the cert when created. This function will create PKCS12 files.
        .INPUTS
        $cert is the path to the certificate file
        $key is the path to the key file
        $p12 is the path to the p12 file you want to store the cert and key in
        $alias is the alias (friendly name) you want to give the cert in the P12 file. Optional if you don't want to provide an alias.
        $keypw is the password to the key file. Optional if the password is blank.
        $p12pw is the password you want to assign to the p12 file. Optional if you want to leave the password blank.
        .OUTPUTS
        A P12 file containing the cert and key, the alias provided, and the password
    #>
    Param
    (
        [Parameter(Mandatory = $true)] [string] $cert,
        [Parameter(Mandatory = $true)] [string] $key,
        [Parameter(Mandatory = $true)] [string] $p12,
        [Parameter(Mandatory = $false)] [string] $alias,
        [Parameter(Mandatory = $false)] [string] $keypw,
        [Parameter(Mandatory = $false)] [string] $p12pw
    )
    openssl pkcs12 -export -in $cert -inkey $key -out $p12 -name $alias -passin pass:$keypw -passout pass:$p12pw
}
#endregion Function Initialize-P12

#region Funciton defaultPassword   
function defaultPassword ($pass){
<#
    Will return true if the password is equal to 'default' and false if it is
#> 
    return ($pass -eq 'default')
}
#endregion Function defaultPassword

#region Function Initiialize-CertReqConfigFile
function Initialize-CertReqConfigFile ($CertInfo) {
        #Delete the config file
        remove-item $configFilePath -Force -ErrorAction Ignore        
        #Set up the req section in the config file
        write-config '[req]'
        write-config 'default_bits = 2048'
        write-config 'default_md = sha256'
        write-config 'prompt = no'
        if (defaultPassword $clearPass){
            write-config 'encrypt_key = no'
        }
        else {  
            write-config 'encrypt_key = yes'
        }
        write-config 'days = 365'
        write-config 'distinguished_name = req_distingquished_name'
        write-config 'req_extensions = req_ext'
        write-config ''

        #req_distinguished_name section
        write-config '[req_distingquished_name]' 
        write-config 'OU = CONTRACTOR'
        write-config 'OU = PKI'
        write-config 'OU = DoD'
        write-config 'O = U.S. Government' 
        write-config 'C = US' 
        $CN = "CN = $($CertInfo.fname).$($CertInfo.lname).$($CertInfo.mi)$($CertInfo.gen).$($CertInfo.dodid)"
        write-config $CN        
        write-config '' 
        
        # req_ext section
        write-config '[req_ext]' 
        write-config 'subjectAltName = @alt_names'
        write-config 'basicConstraints = CA:FALSE'
        write-config 'keyUsage = nonRepudiation, digitalSignature'
        write-config 'extendedKeyUsage = clientAuth, 1.3.6.1.5.5.7.3.4'
        write-config ''
        
        #alt_names section
        write-config '[alt_names]'
        
        # create the email extension
        $RFC822Name = 'email = ' + $certrequests[$i].san
        write-config $RFC822Name
        
        # create the Principal Name extension
        $PrincipalName = 'otherName = 1.3.6.1.4.1.311.20.2.3;UTF8:' + $certrequests[$i].DODID + '@mil'
        write-config $PrincipalName

        # create the path to the unique key file
        $keyfile = $keyExportPath + '\' + $certrequests[$i].alias + '.key'
        # create the path to the unique CSR file
        $csrfile = $batchPath + '\' + $certrequests[$i].alias + '.csr'

        # Generate the new key and CSR file.
        invoke-openssl $configFilePath, $keyfile, $csrfile
}
#endregion Function Initiialize-CertReqConfigFile    

#region Function Write-Lines
function Write-Lines {

    write-host ('-' * 80) -ForegroundColor Cyan 
}
#endregion Function Write-Line

#region Function Copy-CSVfile
function Copy-CSVfile () {

    if (-not $(test-path $CSVFilePath)){
        Copy-Item -path $CSVFile -destination "$rootPath"
    }
    elseif ($OverwriteCSV) {
        Copy-Item -path $CSVFile -destination "$rootPath" -Force
    }    
}
#endregion Function Copy-CSVFile

#region Function Initialize-100dirs
function Initialize-100dirs ($maxItems) {

    for ($i=0; $i -lt $maxItems; $i+=100){
        $min = $i + 1
        $max = $i + 100
        $apath = "Certs-$min-$max"
        Initialize-MissingDirectory "$zipExportPath\$apath"
    }
}
#endregion Function Initialize-100dirs

#region Function Move CSR files 
function Move-CSRFiles (){
   
    $maxItems = $certrequests.length
    initialize-100dirs $maxItems
    #Need to start at 1 because the first subdirectory is Certs-1-100.
    $i=1
    while (Get-ChildItem $csrExportPath){
        $moveFiles = Get-ChildItem -File | Select-Object -first 100
        foreach ($file in $moveFiles){
            Move-Item -Path $file -Destination "$zipExportPath\Certs-$i-$($i+100)"
        }
        #Need to increment $i by 100 to get to the next directory. For example, the second directory is Certs-101-200.
        $i+=100
    }
}
#endregion Function Move CSR files

#region Function Intialize-Keystore
function Initialize-Keystore (){
    Param
    (
        [Parameter(Mandatory)] [string] $srcKeyStore,
        [Parameter(Mandatory)] [string] $srcAlias,
        [Parameter(Mandatory)] [string] $srcPass,
        [Parameter(Mandatory)] [string] $srcKeyPass,
  
        [Parameter(Mandatory)] [String] $destStore,
        [Parameter(Mandatory)] [string] $destStorePass,
        [Parameter(Mandatory)] [string] $destKeyPass
    )

    & 'c:\program files\java\jre1.8.0_341\bin\keytool.exe' -importkeystore -srckeystore $srcKeyStore -srcalias $srcAlias -srcstorepass $srcPass -srckeypass $srcKeyPass -destkeystore $destStore -deststorepass $destStorePass -destkeypass $destKeyPass -noprompt
}
#endregion Function Initialize-Keystore
#endregion Functions

#region main

#region Create Missing Directories and Copy CSV File
write-host "Creating missing directories"
Initialize-MissingDirectory $outputFolderPath
Initialize-MissingDirectory $keyExportPath
Initialize-MissingDirectory $csrExportPath 
Initialize-MissingDirectory $zipExportPath
Initialize-MissingDirectory $certExportPath
Initialize-MissingDirectory $p12ExportPath

#endregion Create Missing Directories and Copy CSV File

#region Read CSV file and update Generation
if ($CreateCSR -or $RenameFiles -or $CreateP12 -or $CreateKeyStore){
    write-host "Reading CSV file"
    copy-csvfile
    $certrequests = Read-CSV
    write-host "Updating the Generation field"
    # Update fields in array
    for ($i=0; $i -lt $certrequests.length; $i++) {
        $certrequests[$i].gen = Update-Field $certrequests[$i].gen 
    }
}
#endregion Read CSV file and update Generation

#region Prompt, Read, and set up passwords
    if ($Password){
        $Pass = Read-Host -AsSecureString -Prompt "Please enter the password for the private key."
    }
    else{
        $Pass = $(ConvertTo-SecureString -AsPlainText -String "default" -Force)
    }
    if ($P12PW){
        $P12Pass = Read-Host -AsSecureString -Prompt "Please enter the password for the PKCS12 file."
    }
    else{
        $P12Pass = $(ConvertTo-SecureString -AsPlainText -String "default" -Force)
    }
    if ($KSPW){
        $KSPass = Read-Host -AsSecureString -Prompt "Please enter the password for the Java Keystore."
    }
    else{
        $KSPass = $(ConvertTo-SecureString -AsPlainText -String "default" -Force)
    }

    $creds = New-Object System.Management.Automation.PSCredential("dummy", $Pass) 
    $clearPass = $creds.GetNetworkCredential().Password
    write-host "Password is $clearPass"

    $P12creds = New-Object System.Management.Automation.PSCredential("dummy", $P12Pass) 
    $P12Clear = $P12creds.GetNetworkCredential().Password
    
    $KWcreds = New-Object System.Management.Automation.PSCredential("dummy", $KSPass) 
    $KPClear = $Kwcreds.GetNetworkCredential().Password

#endregion Prompt, Read, and set up passwords

#region Create the CSR and Key files
if ($CreateCSR){
    write-host "Creating CSRs and Keys"
    foreach ($cert in $certrequests){
        Initialize-CertReqConfigFile ($cert)
        write-lines
        write-host "Creating Certificate and Key file for $($cert.fname).$($cert.lname).$($cert.mi)$($cert.gen).$($cert.DODID)"
        write-host "CSR Filename: $($cert.alias).csr, KEY filename $($cert.alias).key"
        write-host "Creating certificate and key for $($cert.alias)"
        Invoke-OpenSSL $configFilePath "$keyExportPath\$($cert.alias).key" "$csrExportPath\$($cert.alias).csr" $clearPass
    }
    Move-CSRFiles
}
#endregion Create the CSR and Key Files

#region Create the Zip files
if ($ZIP){
    write-host "Zipping up the CSRs and Keys"
    foreach($dir in $(Get-ChildItem $zipExportPath -Directory)){
        Invoke-Zip "$dir.zip" $dir
    }    
}
#endregion Create the Zip files

#region Unzip the files
if ($Unzip){
    write-host "Unzipping the Certificate files from NPE"
    # Unzip all Certs
    $zipFiles = Get-ChildItem -File -Filter "*.zip" $NPECertDownloadsDir
    foreach ($zipFileName in $zipFiles){
        write-host "Unzipping $($zipfilename.fullname)"
        Invoke-Unzip $($ZipFileName.fullname) $certExportPath
    }
}
#endregion Unzip the files

#region Rename the CERT files
if ($RenameFiles){
    write-host "Renaming the certificate files"
    # Rename cert files
    Rename-Certificates $certrequests
}
#endregion Rename the CERT files

#region Create the PKCS12 file
if ($CreateP12){
    write-host "Creating the P12 files"
    # Create PKCS12 files
    $i=0
    foreach ($certreq in $certrequests){
    $alias = "$($certreq.alias)"
    $cert = "$certExportPath\$alias.cer"
    $key = "$keyExportPath\$alias.key"
    $p12 = "$p12ExportPath\$alias.p12"
    #$friendly = $certreq.fname +'.' + $certreq.lname +'.' + $certreq.mi + $certreq.gen +'.' + $certreq.dodid + "'s u.s. government id" 
    $friendly = $alias
    Initialize-P12 $cert $key $p12 $friendly $clearPass $P12Clear
    # $i++
    # if ($i -eq 15){break}
    }
}
#endregion Create the PKCS12 file

#region Add PKCS12 files to keystore
if ($CreateKeyStore){
    write-host "Merging the P12 files into the java keystore"
    # Merge PKCS12 files into Java Keystore
    foreach ($certreq in $certrequests){
        $srcKeyStore = "$p12ExportPath\$($certreq.alias).p12"
        $srcAlias = "$($certreq.alias)"
        $srcPass = $P12Clear
        $srcKeyPass = $clearPass
        $destKeyPass = $KPClear
        $destStorePass = $KPClear
        Initialize-Keystore $srcKeyStore $srcAlias $srcPass $srcKeyPass $destKeyStore $destStorePass $destKeyPass
    }
}
#endregion Add PKCS12 files to keystore

#endregion main
cd C:\users\sjhar\dropbox\Desktop