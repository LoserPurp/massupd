#Defines the new command name
$newCommandName = "massupd"

#Get the current script directory
$scriptDirectory = $PSScriptRoot

#Defines the source folder
$sourceFolder = $scriptDirectory

#Defines the destination folder in Program Files
$destinationFolder = "C:\Program Files\$newCommandName"

#Function to check if the script is run as an administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

#Checks if the script is running as administrator
if (-Not (Test-Administrator)) {
    Write-Warning "This script is not running as administrator. Please run it as administrator."
    Exit
}

#Ensure the source folder exists
if (-Not (Test-Path -Path $sourceFolder)) {
    Write-Error "Source folder does not exist: $sourceFolder"
    Exit 1
}

#Ensure the destination folder does not already exist to avoid overwriting
if (Test-Path -Path $destinationFolder) {
    Write-Error "Destination folder already exists: $destinationFolder"
    Exit 1
}

#Move the folder to Program Files
try {
    Write-Output "Moving folder from $sourceFolder to $destinationFolder"
    Copy-Item -Path $sourceFolder -Destination $destinationFolder -Recurse -Force
    Write-Output "Folder copied successfully to: $destinationFolder"
} catch {
    Write-Error "Failed to move the folder: $_"
    Exit 1
}

#Define the path to the Python file after moving
$pythonFilePath = "$destinationFolder\massupd.py"

#Define new requirements path
$requirementsFilePath = "$destinationFolder\requirements.txt"

#Checks if requirements.txt exists
if (-Not (Test-Path $requirementsFilePath)) {
    Write-Output "requirements.txt not found at $requirementsFilePath. Please provide the requirements.txt file in the script directory."
    Exit
}

#Installs required Python packages
try {
    Write-Output "Installing required Python packages from $requirementsFilePath"
    & pip install -r $requirementsFilePath
    Write-Output "Python packages installed successfully."
} catch {
    Write-Error "Failed to install Python packages: $_"
    Exit 1
}

$batchFilePath = "C:\Windows\$newCommandName.bat"

$batchFileContent = "@echo off`r`npython `"$pythonFilePath`" %*"

#Checks if the batch file already exists
if (-Not (Test-Path $batchFilePath)) {
    #Creates the batch file
    Set-Content -Path $batchFilePath -Value $batchFileContent
    Write-Output "Batch file created: $batchFilePath"
} else {
    Write-Output "Batch file already exists: $batchFilePath"
}

#Gets the current environment variable
$currentPath = [System.Environment]::GetEnvironmentVariable("PATH", [System.EnvironmentVariableTarget]::Machine)

$windowsDirectory = "C:\Windows"
if ($currentPath.Split(";") -notcontains $windowsDirectory) {
    $newPath = "$currentPath;$windowsDirectory"

    #Sets the environment variable
    [System.Environment]::SetEnvironmentVariable("PATH", $newPath, [System.EnvironmentVariableTarget]::Machine)

    Write-Output "The directory $windowsDirectory has been added to the PATH environment variable."
} else {
    Write-Output "The directory $windowsDirectory is already in the PATH environment variable."
}