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
  CSVFilePath the CSV file that contains the certificate request details.
  
 .PARAMETER CSRRootDir
  CertRootDir is the root directory where all of the files pertaining to this script will be kept. This is a relative path or a full path. 

 .PARAMETER CSRDir
 CSRDir is the directory where the CSR files will be created. This is a subdirectory of CSRRootDir and is relative path.

 .PARAMETER KeyDir
 KeyDir is the directory where the Key files will be created. This is a subdirectory of CSRRootDir and is relative path.

 .PARAMETER Password
 A SecureString password to be used as the private key password or the P12 password

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
    [Parameter(Mandatory)] [String]$rootPath,
    [Parameter(Mandatory)] [String]$CSVFile,
    [String]$CSRDir,
    [String]$KeyDir,
    [SecureString]$Password,
    [Switch]$CreateCSR,
    [Switch]$ZIP,
    [Switch]$Unzip,
    [Switch]$CreateP12,
    [Switch]$CreateKeyStore,
    [Switch]$RenameFiles,
    [Switch]$OverwriteCSV

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
#endregion Set up variables


function Write-Config ($string){ 
#region Write-Config
    <#
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
#endregion Write-Config
}


function Initialize-MissingDirectory ($dir){
 #region Initialize-MissingDirectory
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
#endregion Initialize-MissingDirectory
}


function Update-Field ($certField){
#region Update-Field
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
#endregion Update-Field
}


function Read-CSV () {
#region Read-CSV
    <#
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
#endregion Read-CSV
}


function Invoke-OpenSSL ($configFilePath, $keyfile, $csrfile) {
#region Invoke-OpenSSL
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
    & openssl req -new -config $configFilePath -newkey rsa:2048 -keyout $keyfile -out $csrfile
#endregion Invoke-OpenSSL
}


function Invoke-Zip ($ZipFileName, $ZipDir){
#region Invoke-Zip
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
#endregion Invoke-Zip
}

function Invoke-Unzip ($ZipFileName, $ZipDir){
#region Invoke-Unzip
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
    & 'C:\Program Files\7-Zip\7z.exe' e $ZipFileName $dir
#endregion Invoke-Unzip
}


function Rename-Certificates ($certrequests) {
#region Rename-Certificate
    <#
        .SYNOPSIS
        Rename the CER files that NPE returned
        .DESCRIPTION
        NPE returns CER files named to match the CN of the certifcate. This can be a very long filename and can be renamed to match a shorter name. The CSV file has an alias field. 
        You could used the alias field as a potential new name for the cert file.
        .OUTPUTS
        All certs in the Cert directory will be renamed
    #>
    
    foreach ($cert in $certrequests){
        Update-Field $cert.gen
        $oldName = $certrequests[$i].fname +'.' + $certrequests[$i].lname +'.' + $certrequests[$i].mi + $certrequests[$i].gen +'.' + $certrequests[$i].dodid + ".cer"
        $newName = $certrequests[$i].alias + ".cer"
        Rename-Item -Path $oldName -NewName $newName
    }
#endregion Rename-Certificates
}


function Initialize-P12 {
#region Iniitialize-P12
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

        openssl pkcs12 -export -in $cert -inkey $key -out $p12 -name $alias -passout pass:$p12pw -passin pass:$keypw
#endregion Initialize-P12
}


function Initialize-CertReqConfigFile ($CertInfo) {
#region Initiialize-CertReqConfigFile
 
        #Delete the config file
        remove-item $configFilePath -Force -ErrorAction Ignore
        
        #Set up the req section in the config file
        write-config '[req]'
        write-config 'default_bits = 2048'
        write-config 'default_md = sha256'
        write-config 'prompt = no'
        write-config 'encrypt_key = no'
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
        
        
        
        $CN = 'CN = ' + $certrequests[$i].fname +'.' + $certrequests[$i].lname +'.' + $certrequests[$i].mi + $certrequests[$i].gen +'.' + $certrequests[$i].dodid
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

#endregion Initiialize-CertReqConfigFile    
}


function Write-Lines {
#region Write-Lines
    write-host ('-' * 80) -ForegroundColor Cyan 
#endregion Write-Line
}


function Copy-CSVfile () {
#region Copy-CSVfile
    if (-not $(test-path $configFilePath)){
        Copy-Item -path $CSVFile -destination "$rootPath"
    }
    elseif ($OverwriteCSV) {
        Copy-Item -path $CSVFile -destination "$rootPath" -Force
    }    
#endregion Copy-CSVFile
}


function Initialize-100dirs ($maxItems) {
#region Initialize-100dirs
    for ($i=0; $i -lt $maxItems; $i+=100){
        $min = $i + 1
        $max = $i + 100
        $apath = "Certs-$min-$max"
        Initialize-MissingDirectory "$zipExportPath\$apath"
    }
#endregion Initialize-100dirs
}


#region main

#region Create Missing Directories and Copy CSV File
write-host "Creating missing directories"
Initialize-MissingDirectory $outputFolderPath
Initialize-MissingDirectory $keyExportPath
Initialize-MissingDirectory $csrExportPath 
copy-csvfile
#endregion Create Missing Directories and Copy CSV File

#region Read CSV file
write-host "Reading CSV file"
$certrequests = Read-CSV
#endregion Read CSV file

#region Update the Generation Field
write-host "Updating the Generation field"
# Update fields in array
    for ($i=0; $i -lt $certrequests.length; $i++) {
        $certrequests[$i].gen = Update-Field $certrequests[$i].gen 
    }
#endregion Update the Generation Field

#region Create the CSR and Key files
if ($CreateCSR){
    write-host "Creating CSRs and Keys"
    foreach ($cert in $certrequests){
        Initialize-CertReqConfigFile ($cert)
        write-lines
        write-host "openssl config file for $($cert.fname) $($cert.lname)"
        foreach($line in [System.IO.File]::ReadLines($configFilePath))
        {
            Write-Host $line -ForegroundColor White -BackgroundColor Black
        }
        Invoke-OpenSSL $configFilePath "$csrExportPath\$($cert.alias).key" "$keyExportPath\$($cert.alias).csr"
    }
}
#endregion Create the CSR and Key files

#region Create the Zip files
if ($ZIP){
    write-host "Zipping up the CSRs and Keys"
    $maxItems = $certrequests.length
    initialize-100dirs $maxItems
    foreach($dir in $(Get-ChildItem $zipExportPath -Directory)){
        Invoke-Zip "$dir.zip" $dir
    }    
}
#endregion Create the Zip files

#region Unzip the files
if ($Unzip){
    write-host "Unzipping the Certificate files from NPE"
    write-host "SKIPPING"
    # Unzip all Certs
    #Invoke-Unzip $ZipFileName, $ZipDir
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
    foreach ($certreq in $certrequests){
    $alias = $certreq.alias
    $cert = "$alias.cer"
    $key = "$alias.key"
    $p12 = "$alias.p12"
    $friendly = $certreq.fname +'.' + $certreq.lname +'.' + $certreq.mi + $certreq.gen +'.' + $certreq.dodid + "'s u.s. government id" 
    $keypw = 'password'
    $p12pw = 'password'
    Initialize-P12 $cert $key $p12 $friendly $keypw $p12pw 
    }
}
#endregion Create the PKCS12 file

#region Add PKCS12 files to keystore
if ($CreateKeyStore){
    write-host "Mertging the P12 files into the java keystore"
    write-host "SKIPPING"
    # Merge PKCS12 files into Java Keystore
    $allFiles = Get-ChildItem -Path $certZipPath
    Push-Location $certZipPath
    foreach ($file in $allfiles){
        $thisZip = $("$($file.directoryname)\$($file.name)")
        Invoke-Unzip $thisZip 
    }
}
#endregion Add PKCS12 files to keystore

#endregion main