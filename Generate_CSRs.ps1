<#
 .SYNOPSIS
  This PowerShell script is to generate certificate signing requests with corresponding keys in bulk using a comma separated values input file.
  

 .DESCRIPTION
  Create bulk CSRs and Keys using a CSV file as input. Zip files are created with the maximum of 100 CSRs per zip to enable compatibility with uploading to the DoD NPE-Portal for Bulk Submit.


 .PARAMETER CSVFilePath
  CSVFilePath is the path to the CSV file that contains the certificate request details.

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
  about_functions_advanced

 .LINK
  about_comment_based_help

#>

#Function to write the config file.
function Write-Config ($string){ 
    write-ouput $string | Out-File $configFilePath -Append -Encoding utf8
}


# This function will create the missing directories
function Initialize-MissingDirectory ($dir){
# if the exportFolderPath doesn't exist, make it
    if ( -not $(test-path $dir) ) {
        write-host "Creating $dir"
        New-Item -Path $dir -ItemType Directory
    }
    else {
        write-host "$dir already exists"
    }
}

# This function will ensure that the generation has a period (.) in it if the generation is not empty.
function Update-Field ($certgen){
    if ( $certgen -ne '' )
    {
        $fixed = '.' + $certgen
    }
    else {
        $fixed = $certgen
    }
    return $fixed
}

function Read-CSV ($csvpath){
    # Import the csv file into an array
    $certrequests = Import-CSV $importFilePath
    return $certrequests
}

function Invoke-OpenSSL ($configFilePath, $keyfile, $csrfile) {
    & openssl req -new -config $configFilePath -newkey rsa:2048 -keyout $keyfile -out $csrfile
}

#Zip up the files in batches of 100 to submit in bulk to NPE
function Invoke-Zip ($ZipFileName, $ZipDir){
    & 'C:\Program Files\7-Zip\7z.exe' a $ZipFileName $dir\*
}

function Invoke-Unzip ($ZipFileName, $ZipDir){
    & 'C:\Program Files\7-Zip\7z.exe' e $ZipFileName $dir
}

# This function will rename the certificate files from the filename that NPE issues the certificates in
# to the alias found in the spreadsheet.
function rename-certificates {
    $certrequests = import-csv $importFilePath
    for ($i=0; $i -lt $certrequests.Length ; $i++){
        if ( $certrequests[$i].gen -ne '' )
        {
            $certrequests[$i].gen = '.' + $certrequests[$i].gen
        }

        $oldName = $certrequests[$i].fname +'.' + $certrequests[$i].lname +'.' + $certrequests[$i].mi + $certrequests[$i].gen +'.' + $certrequests[$i].dodid + ".cer"
        $newName = $certrequests[$i].alias + ".cer"
        Rename-Item -Path $oldName -NewName $newName
    }
}

#This function will create p12 (pkcs12) files from the certs and keys.
function Initialize-P12 {
    $certrequests = import-csv $importFilePath
    cd 'C:\Users\sjhar\OneDrive - Alesig Consulting LLC\DISA\USN Certificate Generation Task\Issued Certificates'
    foreach ($certreq in $certrequests){
        if ( $certreq.gen -ne '' )
        {
            $certreq.gen = '.' + $certreq.gen
        }

        $alias = $certreq.alias
        $cert = "$alias.cer"
        $key = "$alias.key"
        $p12 = "$alias.p12"
        $friendly = $certreq.fname +'.' + $certreq.lname +'.' + $certreq.mi + $certreq.gen +'.' + $certreq.dodid + "'s u.s. government id" 
        openssl pkcs12 -export -in $cert -inkey $key -out $p12 -name $friendly -passout pass:password
    }

}

# loop through all 8500 lines of the newly created array
# This is the major part of the script.
# It basically deletes the openssl.cfg file, then recreates it with all of the required
# data to create a csr for the current item in the array. 
# after it makes the cfg file, it will execute openssl with that file to make a new key and csr file.

function Initialize-CertReqConfigFile ($CertInfo) {

        $certrequests[$i].gen = fix-generation($certrequests[$1].gen)
    
        # Create a directory for the first 100 CSRs, and every 100 after that
        if ($i % 100 -eq 0){
            $min = $i + 1
            $max = $i + 100
            $apath = "Certs-$min-$max"
            Create-100dir ($apath)
            $batchPath = "$csrExportPath\$apath"
        }

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
        call-openssl $configFilePath, $keyfile, $csrfile

    }
}

function Initialize-Variables {
    # Path variables
    #rootPath is the top level directory where all of this stuff takes place
    $global:rootPath = 'C:\Users\sjhar\OneDrive - Alesig Consulting LLC\DISA\USN Certificate Generation Task'
    #ImportFilePath is the path to the csv file that has all of the cert requirements on it.
    $global:importFilePath = "$global:rootPath\8500 Certs.csv"
    #exportFolderPath is the path where files are created (including subdirs)
    $global:exportFolderPath = "$global:rootPath\8500 CSRs"
    #csrExportPath is the directory where the CSR files and subdirectories are created.
    $global:csrExportPath = "$global:exportFolderPath\CSRs"
    #keyExportPath is the directory to hold all of the generated key files.
    $global:keyExportPath = "$global:exportFolderPath\Keys"
    #condifFilePath is the path to the openssl.cfg file that this script repeatedly creates
    $global:configFilePath = "$global:rootPath\openssl.cfg"

}

# Step 1
# Setup Script Variables and create missing directories.
Initialize-Variables
Initialize-MissingDirectory $exportFolderPath
Initialize-MissingDirectory $keyExportPath
Initialize-MissingDirectory $crsExportPath 

# Step 2
# Get CSV file path

# Step 3
# Read CSV file

# Step 4 
# Update fields in array

# Step 5
# Create CSRs with Keys
    # Loop
        foreach ($User in $global:certrequests){
            Initialize-CertReqConfigFile ($User)
            Invoke-OpenSSL $global:configFilePath $global:keyfile $Global:cert
        }
    # End Loop


# Loop
    # Step 5a
    # Create Config File

    # Step 5b
    # Create key and csr
# End Loop

# Step 6
# Zip all CSRs

# Step 7
# Unzip all Certs

# Step 8
# Rename cert files

# Step 9
# Create PKCS12 files

# Step 10
# Merge PKCS12 files into Java Keystore


$allFiles = Get-ChildItem -Path $certZipPath
Push-Location $certZipPath
foreach ($file in $allfiles){
    $thisZip = $("$($file.directoryname)\$($file.name)")
    Invoke-Unzip $thisZip 
}