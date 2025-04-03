#!/bin/bash
#######################################################################
# Shellscript     :   Patch Helper
# Edetiert durch  :   Andreas Vogel
# Changelog			: 	0.1    -	initial skript
#                   :   0.2     -   Termination of the LaunchDaemon via bootout
#                   :   0.3     -   Retrieve customization of PolicyNames via API
#                   :   0.4     -   Adjustment of the icons so that they use the correct icon in the "case" function
#                   :   0.5     -   Adjustment of the JSON so that it always executes the policy for Update Inventory at the end..
#                   :   0.6     -   Added function for "invalidateToken" so that the token is automatically discarded on exit.
#                   :   0.7     -   Customization of the icon 
#                   :   0.8     -   Safari (has been removed again)
#					:	0.9     -	Translation, Redigatur
#                   :   0.9.1   -   Counter is changed as $Update_Count so that only the number of updates is displayed and
#                                   no longer the number of all steps (incl. the update inventory)
#                   :   0.9.2   -   Adding the new variable $BundelID, this now checks whether the affected application is running or not.
#                                   is executed or not. If the application is not executed, it will be executed immediately via the 
#                                   jamf policy -id will be executed immediately. If it is executed or the $BundelID variable is empty,
#                                   is empty, this is included in the json and the user is informed. If all applications to be patched are not 
#                                   are executed, all policies are executed in the background and the user is not aware of this. 
#
#######################################################################
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Internal IT contacts
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
Support_Telefon="+49 12 3456 789"
Support_Email="support@nextenterprise.it"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Script Version and Jamf Pro Script Parameters
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
scriptVersion="0.9.3"
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
scriptLog="/var/log/it.next_patch_management.log"


if [[ ! -f "${scriptLog}" ]]; then
    touch "${scriptLog}"
fi

debugMode="${4:-"false"}"                                 # Parameter 4: Debug Mode [ true (default) | false ]

BannerImage="${5}"                                        # Parameter 5: BannerImage on Top of swiftDialog
if [[ -z "$BannerImage" ]]; then
    BannerImage="https://ics.services.jamfcloud.com/icon/hash_cfbe99281c08b7ef85da92dcb56be11a6ff8562e37d24bb20ecf230495d617df"
fi

InfoboxIcon="${6}"                                        # Parameter 6: InfoboxIcon Icon on left Site of swiftDialog
if [[ -z "$InfoboxIcon" ]]; then
    InfoboxIcon="https://ics.services.jamfcloud.com/icon/hash_0b3ab277243d56f8bbe486f3453ba6c4fa9ea53f50245597f7852b62624d2bc6"
fi

StartInterval="${7}"
if [[ -z "$StartInterval" ]]; then
    StartInterval="3600"
fi


UpdateDeferral_Value="${8}"
if [[ -z "$UpdateDeferral_Value" ]]; then
    UpdateDeferral_Value="4"
fi

TimePromtUser="${9}"
if [[ -z "$TimePromtUser" ]]; then
    TimePromtUser="300"
fi

profilesSTATUS=$(profiles status -type enrollment 2>&1)
jamfpro_url="https://$(echo "$profilesSTATUS" | grep 'MDM server' | awk -F '/' '{print $3}')"
if [[ -z "$jamfpro_url" ]]; then
    echo "Jamf Pro URL missing"
    exit 1
fi

encodedCredentials="${11}"
if [[ -z "$encodedCredentials" ]]; then
    echo "Credentials missing"
    exit 1
fi

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# ****************************** Testing *********************************************************************#

#encodedCredentials=""
#if [[ -z "$encodedCredentials" ]]; then
#   echo "Credentials missing"
#   exit 1
#fi

# ****************************** End Testing *****************************************************************#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

UserInformation="promtUserInfo"                     # PROMT USER DIALOG [ promtUserInfo (default) | false ]
completionActionOption="wait"                       # Completion Action [ wait | Close ]

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Operating System, currently logged-in user and default Exit Code
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
osVersion=$( sw_vers -productVersion )
osBuild=$( sw_vers -buildVersion )
osMajorVersion=$( echo "${osVersion}" | awk -F '.' '{print $1}' )
reconOptions=""
exitCode="0"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#
# WARM-UPs
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# # # # # # # # # # # # # # # Client-side Script Logging Function  # # # # # # # # # # # # # # # # #
function updateScriptLog() {
    echo -e "$( date +%Y-%m-%d\ %H:%M:%S ) - ${1}" | tee -a "${scriptLog}"
}
# # # # # # # # # # # # # # # Current Logged-in User Function  # # # # # # # # # # # # # # # # # # #
function currentLoggedInUser() {
    loggedInUser=$( echo "show State:/Users/ConsoleUser" | scutil | awk '/Name :/ { print $3 }' )
    updateScriptLog "PRE-FLIGHT CHECK: Current Logged-in User: ${loggedInUser}"
}
# # # # # # # # # # # # # # # Confirm script is running as root # # # # # # # # # # # # # # # # # #
if [[ $(id -u) -ne 0 ]]; then
    updateScriptLog "WARM-UP: This script must be run as root; exiting."
    exit 1
fi
## # # # # # # # # # # # # # # Ensure computer does not go to sleep during SYM # # # # # # # # # # # #
#updateScriptLog "WARM-UP: Caffeinating this script (PID: $$)"
#caffeinate -dimsu -w $$ &
# # # # # # # # # # # # # # # Validate Logged-in System Accounts # # # # # # # # # # # # # # # # # # #
updateScriptLog "PRE-FLIGHT CHECK: Check for Logged-in System Accounts …"
currentLoggedInUser

counter="1"

until { [[ "${loggedInUser}" != "_mbsetupuser" ]] || [[ "${counter}" -gt "180" ]]; } && { [[ "${loggedInUser}" != "loginwindow" ]] || [[ "${counter}" -gt "30" ]]; } ; do
    
    updateScriptLog "PRE-FLIGHT CHECK: Logged-in User Counter: ${counter}"
    currentLoggedInUser
    sleep 2
    ((counter++))
    
done

loggedInUserFullname=$( id -F "${loggedInUser}" )
loggedInUserFirstname=$( echo "$loggedInUserFullname" | sed -E 's/^.*, // ; s/([^ ]*).*/\1/' )
loggedInUserID=$( id -u "${loggedInUser}" )
updateScriptLog "PRE-FLIGHT CHECK: Current Logged-in User First Name: ${loggedInUserFirstname}"
updateScriptLog "PRE-FLIGHT CHECK: Current Logged-in User ID: ${loggedInUserID}"
# # # # # # # # # # # # # # # # # # Validate swiftDialog is install # # # # # # # # # # # # # # # #
function dialogCheck() {

    # Output Line Number in `true` Debug Mode
    if [[ "${debugMode}" == "true" ]]; then updateScriptLog "WARM-UP: # # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi

    # Get the URL of the latest PKG From the Dialog GitHub repo
    # dialogURL=$(curl --silent --fail --location "https://api.github.com/repos/bartreardon/swiftDialog/releases/latest" | awk -F '"' "/browser_download_url/ && /pkg\"/ { print \$4; exit }")
        
    dialogURL="https://github.com/swiftDialog/swiftDialog/releases/download/v2.2.1/dialog-2.2.1-4591.pkg"
    
    # Expected Team ID of the downloaded PKG
    expectedDialogTeamID="PWA5E9TQ59"

    # Check for Dialog and install if not found
    if [ ! -e "/Library/Application Support/Dialog/Dialog.app" ]; then

        updateScriptLog "PRE-FLIGHT CHECK: Dialog not found. Installing..."

        # Create temporary working directory
        workDirectory=$( /usr/bin/basename "$0" )
        tempDirectory=$( /usr/bin/mktemp -d "/private/tmp/$workDirectory.XXXXXX" )

        # Download the installer package
        /usr/bin/curl --location --silent "$dialogURL" -o "$tempDirectory/Dialog.pkg"

        # Verify the download
        teamID=$(/usr/sbin/spctl -a -vv -t install "$tempDirectory/Dialog.pkg" 2>&1 | awk '/origin=/ {print $NF }' | tr -d '()')

        # Install the package if Team ID validates
        if [[ "$expectedDialogTeamID" == "$teamID" ]]; then

            /usr/sbin/installer -pkg "$tempDirectory/Dialog.pkg" -target /
            sleep 2
            dialogVersion=$( /usr/local/bin/dialog --version )
            updateScriptLog "PRE-FLIGHT CHECK: swiftDialog version ${dialogVersion} installed; proceeding..."

        else

            # Display a so-called "simple" dialog if Team ID fails to validate
            osascript -e 'display dialog "Please advise your Support Representative of the following error:\r\r• Dialog Team ID verification failed\r\r" with title "Patch Helper: Error" buttons {"Close"} with icon caution'
            completionActionOption="Quit"
            exitCode="1"
            quitScript

        fi

        # Remove the temporary working directory when done
        /bin/rm -Rf "$tempDirectory"

    else

        updateScriptLog "PRE-FLIGHT CHECK: swiftDialog version $(/usr/local/bin/dialog --version) found; proceeding..."

    fi

}

if [[ ! -e "/Library/Application Support/Dialog/Dialog.app" ]]; then
    dialogCheck
else
    updateScriptLog "PRE-FLIGHT CHECK: swiftDialog version $(/usr/local/bin/dialog --version) found; proceeding..."
fi
########################################################################
## Deferral Handling
########################################################################

setDeferral (){
    BundleID="${1}"
    DeferralType="${2}"
    UpdateDeferral_Value="${3}"
    DeferralPlist="${4}"
    
    if [[ "$DeferralType" == "date" ]]
    then
        DeferralDate="$(/usr/libexec/PlistBuddy -c "print :$BundleID:date" "$DeferralPlist" 2>/dev/null)"
        # Set deferral date
        if [[ -n "$DeferralDate" ]] && [[ ! "$DeferralDate" =~ "File Doesn't Exist" ]]
        then
            # /usr/libexec/PlistBuddy -c "set :$BundleID:date '07/04/2019 11:21:51 +0000'" "$DeferralPlist"
            /usr/libexec/PlistBuddy -c "set :$BundleID:date $UpdateDeferral_Value" "$DeferralPlist" 2>/dev/null
        else
            # /usr/libexec/PlistBuddy -c "add :$BundleID:date date '07/04/2019 11:21:51 +0000'" "$DeferralPlist"
            /usr/libexec/PlistBuddy -c "add :$BundleID:date date $UpdateDeferral_Value" "$DeferralPlist" 2>/dev/null
        fi
    elif [[ "$DeferralType" == "count" ]]; then
        DeferralCount="$(/usr/libexec/PlistBuddy -c "print :$BundleID:count" "$DeferralPlist" 2>/dev/null)"
        # Set deferral count
        if [[ -n "$DeferralCount" ]] && [[ ! "$DeferralCount" =~ "File Doesn't Exist" ]]
        then
            /usr/libexec/PlistBuddy -c "set :$BundleID:count $UpdateDeferral_Value" "$DeferralPlist" 2>/dev/null
        else
            /usr/libexec/PlistBuddy -c "add :$BundleID:count integer $UpdateDeferral_Value" "$DeferralPlist" 2>/dev/null
        fi
    else
        echo "Incorrect deferral type used."
        exit 14
    fi
}

DeferralPlist="/Library/Application Support/JAMF/it.next.PatchHelper.update.deferrals.plist"
BundleID="it.next.PatchHelper"
DeferralType="count"

CurrentDeferralValue="$(/usr/libexec/PlistBuddy -c "print :$BundleID:count" "$DeferralPlist" 2>/dev/null)"
# Set up the deferral value if it does not exist already
if [[ -z "$CurrentDeferralValue" ]] || [[ "$CurrentDeferralValue" =~ "File Doesn't Exist" ]]; then
    setDeferral "$BundleID" "$DeferralType" "$UpdateDeferral_Value" "$DeferralPlist"
    CurrentDeferralValue="$(/usr/libexec/PlistBuddy -c "print :$BundleID:count" "$DeferralPlist" 2>/dev/null)"
fi
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# PRE-FLIGHT CHECK: Complete
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

updateScriptLog "PRE-FLIGHT CHECK: Complete"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# LaunchDaemon Check 
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
LaunchDaemonLabel="it.next.UpdateEnforce"
LaunchDaemonPlist="/Library/LaunchDaemons/$LaunchDaemonLabel.plist"
LaunchDaemonisReady=0

# Prüfe, ob LaunchDaemon-Datei existiert und ob sie geladen ist
if [[ -f "$LaunchDaemonPlist" ]]
    then
        if launchctl list | grep -q "$LaunchDaemonLabel"
            then
                updateScriptLog "LAUNCH-DAEMON FUNCTION: LaunchDaemon '$LaunchDaemonLabel' is already loaded."
                LaunchDaemonisReady=1
            else
                updateScriptLog "LAUNCH-DAEMON FUNCTION: LaunchDaemon-Plist available, but not loaded."
                LaunchDaemonisReady=1
        fi
    else
        updateScriptLog "LAUNCH-DAEMON FUNCTION: LaunchDaemon '$LaunchDaemonLabel' does not exist."
        LaunchDaemonisReady=0
fi

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Language
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
CurrentUser=$(/usr/sbin/scutil <<< "show State:/Users/ConsoleUser" | /usr/bin/awk -F': ' '/[[:space:]]+Name[[:space:]]:/ { if ( $2 != "loginwindow" ) { print $2 }}')
Language=$(/usr/libexec/PlistBuddy -c 'print AppleLanguages:0' "/Users/$CurrentUser/Library/Preferences/.GlobalPreferences.plist")

if [[ $Language != de* ]]
    then
        UserLanguage="EN"
    else
        UserLanguage="DE"
fi

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Helper-Funktionen: Cleanup etc.
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
function ClearUpLaunchDaemon() {
    updateScriptLog "QUIT SCRIPT: Stopping LaunchDaemon via launchctl bootout system …"
    launchctl bootout system/$LaunchDaemonLabel 2>/dev/null
    if [ $? -ne 0 ]
        then
            updateScriptLog "QUIT SCRIPT: Error unloading LaunchDaemon"
        else
            updateScriptLog "QUIT SCRIPT: LaunchDaemon unloaded successfully"
    fi
    
    updateScriptLog "QUIT SCRIPT: delete the LaunchDaemon"
    rm -rf $LaunchDaemonPlist
}

function ClearUpPlist() {
    updateScriptLog "QUIT SCRIPT: Set Deferral Count back to Default."
     rm -rf "/Library/Application Support/JAMF/it.next.PatchHelper.update.deferrals.plist"
}

function ClearUpDeferral() {
    if [[ "$LaunchDaemonisReady" -eq 1 ]]
        then
            updateScriptLog "QUIT SCRIPT: Clean up the daemon, updates were successfully installed …"
            ClearUpPlist
            ClearUpLaunchDaemon
        else
            updateScriptLog "QUIT SCRIPT: Daemon was not set up, user had not yet moved …"
            ClearUpPlist
    fi
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# LaunchDaemon anlegen und starten
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
function createLaunchDaemon() {
    /bin/cat <<EOC > "$LaunchDaemonPlist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Label</key>
<string>${LaunchDaemonLabel}</string>
<key>ProgramArguments</key>
<array>
    <string>/usr/local/jamf/bin/jamf</string>
    <string>policy</string>
    <string>-event</string>
    <string>update</string>
</array>
<key>RunAtLoad</key>
<false/>
<key>StartInterval</key>
<integer>${StartIntervalDaemon}</integer>
<key>UserName</key>
<string>root</string>
</dict>
</plist>
EOC
}

function StartLaunchDaemon() {
    updateScriptLog "LAUNCH-DAEMON FUNCTION: Start the process to change the LaunchDaemon settings."
    updateScriptLog "LAUNCH-DAEMON FUNCTION: Change owner (root:wheel) for $LaunchDaemonPlist."
    if /usr/sbin/chown root:wheel "$LaunchDaemonPlist"
        then
            updateScriptLog "LAUNCH-DAEMON FUNCTION: chown executed successfully."
        else
            updateScriptLog "LAUNCH-DAEMON FUNCTION: ERROR: chown failed."
    fi
    
    updateScriptLog "LAUNCH-DAEMON FUNCTION: Set access rights (644) for $LaunchDaemonPlist."
    if /bin/chmod 644 "$LaunchDaemonPlist"
        then
            updateScriptLog "LAUNCH-DAEMON FUNCTION: chmod executed successfully."
        else
            updateScriptLog "LAUNCH-DAEMON FUNCTION: ERROR: chmod failed."
    fi
    
    updateScriptLog "LAUNCH-DAEMON FUNCTION: Try to load LaunchDaemon."
    if launchctl load "${LaunchDaemonPlist}" 2>/dev/null
        then
            updateScriptLog "LAUNCH-DAEMON FUNCTION: LaunchDaemon has been loaded successfully."
        else
            updateScriptLog "LAUNCH-DAEMON FUNCTION: ERROR: LaunchDaemon could not be loaded."
    fi
    
    updateScriptLog "LAUNCH-DAEMON FUNCTION: Process completed."

}
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Auth / Policies
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
authToken=$(/usr/bin/curl "${jamfpro_url}/api/v1/auth/token" --silent \
--request POST \
--header "Authorization: Basic ${encodedCredentials}")

if [[ $(/usr/bin/sw_vers -productVersion | awk -F . '{print $1}') -lt 12 ]]
    then
        api_token=$(/usr/bin/awk -F \" 'NR==2{print $4}' <<< "$authToken" | /usr/bin/xargs)
    else
        api_token=$(/usr/bin/plutil -extract token raw -o - - <<< "$authToken")
fi

response=$(/usr/bin/curl -X GET \
"$jamfpro_url/JSSResource/computermanagement/udid/$(system_profiler SPHardwareDataType | grep UUID | awk '" " { print $NF }')/subset/policies" \
-H "accept: application/xml" \
-H "Authorization: Bearer ${api_token}")

xmlupdates="/tmp/policies.xml"
echo "$response" > "$xmlupdates"

plistOutput="/tmp/AppUpdates.plist"

# Plist-Header
cat <<EOF > "$plistOutput"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" 
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Applications</key>
<array>
EOF

count=0
while read -r line; do
    id=$(echo "$line" | xmllint --xpath "string(//id)" - 2>/dev/null)
    name=$(echo "$line" | xmllint --xpath "string(//name)" - 2>/dev/null)
    if [[ -n "$id" && -n "$name" ]]; then
        cat <<EOF >> "$plistOutput"
<dict>
    <key>ID</key>
    <string>$id</string>
    <key>Name</key>
    <string>$name</string>
</dict>
EOF
        count=$((count + 1))
    fi
done < <(echo "$response" | xmllint --xpath "//policy[triggers='patch_app_updates']" -)

cat <<EOF >> "$plistOutput"
</array>
<key>ApplicationCount</key>
<integer>$count</integer>
</dict>
</plist>
EOF

function invalidateToken() {
    responseCode=$(
    curl -w "%{http_code}" -H "Authorization: Bearer ${api_token}" \
    "$jamfpro_url/api/v1/auth/invalidate-token" -X POST -s -o /dev/null
)
    if [[ ${responseCode} == 204 ]]; then
        updateScriptLog "QUIT SCRIPT: Token successfully invalidated"
    elif [[ ${responseCode} == 401 ]]; then
        updateScriptLog "QUIT SCRIPT: Token already invalid"
    else
        updateScriptLog "An unknown error occurred invalidating the token"
    fi
}

initial_Update_Count=$(/usr/libexec/PlistBuddy -c "Print :ApplicationCount" "$plistOutput" 2>/dev/null)
updateScriptLog "CHECK-FOR-UPDATES FUNCTION: The total number of updates is: $initial_Update_Count"

if [[ "$initial_Update_Count" -eq 0 ]]; then
    updateScriptLog "CHECK-FOR-UPDATES FUNCTION: no patches found, exiting"
    if [[ "$LaunchDaemonisReady" -eq 1 ]]; then
        updateScriptLog "Entferne existierenden LaunchDaemon (da Updates erfolgreich)."
        ClearUpPlist
        ClearUpLaunchDaemon
    fi
    exit 0
fi

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#
# Dialog Variables
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# infobox-related variables
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
macOSproductVersion="$( sw_vers -productVersion )"
macOSbuildVersion="$( sw_vers -buildVersion )"
serialNumber=$( system_profiler SPHardwareDataType | grep Serial |  awk '{print $NF}' )
timestamp="$( date '+%Y-%m-%d-%H%M%S' )"
dialogVersion=$( /usr/local/bin/dialog --version )

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Reflect Debug Mode in `infotext` (i.e., bottom, left-hand corner of each dialog)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
case ${debugMode} in
    "true"   ) scriptVersion="DEBUG MODE | Dialog: v${dialogVersion} • Patch Helper: v${scriptVersion}" ;;
    "false"   ) scriptVersion="Patch Helper | v${scriptVersion}" ;;
esac

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Set Dialog path, Command Files, JAMF binary, log files and currently logged-in user
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
dialogApp="/Library/Application\ Support/Dialog/Dialog.app/Contents/MacOS/Dialog"
dialogBinary="/usr/local/bin/dialog"
CommandFile=$( mktemp /var/tmp/dialogWelcome.XXX )
PatchHelperCommandFile=$( mktemp /var/tmp/dialogPatchHelper.XXX )
failureCommandFile=$( mktemp /var/tmp/dialogFailure.XXX )
jamfBinary="/usr/local/bin/jamf"

# # # # # # # # # # # # # # # # # # # "Patch Helper" Change Time Value # # # # # # # # # # # # # # # #
updateScriptLog "CHECK-FOR-UPDATES FUNCTION: Read the values for the LaunchDaemon."

if [[ $StartInterval -eq 3600 ]]; then
        updateScriptLog "CHECK-FOR-UPDATES FUNCTION: The update is carried out every hour."
        Time_EN="hourly"
        Time_DE="stündlich"
elif [[ $StartInterval -lt 3600 ]]; then
        # Converted interval in minutes
        intervalMinutes=$((StartInterval / 60))
        
        updateScriptLog "CHECK-FOR-UPDATES FUNCTION: The update is executed every $intervalMinutes minutes."
        
        Time_EN="all $intervalMinutes minutes"
        Time_DE="alle $intervalMinutes Minuten"
else
        # Converted interval in hours and minutes
        intervalHours=$((StartInterval / 3600))
        intervalMinutes=$(( (StartInterval % 3600) / 60 ))
        
        updateScriptLog "CHECK-FOR-UPDATES FUNCTION: The update is forced every $intervalHours hr. $intervalMinutes min."
        
        Time_EN="all $intervalHours Hours $intervalMinutes minutes"
        Time_DE="jede $intervalHours Stunde und $intervalMinutes Minuten"
fi

Time=Time_${UserLanguage}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Baue JSON aus den plist-Einträgen
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
function get_Names_display() {
    /usr/libexec/PlistBuddy -c "Print :Applications" "$plistOutput" | \
    awk -F "Name = " '/Name =/ {
    name=$2
    sub(/^ */, "", name)
    print name
}' | tr '\n' ',' | sed 's/,/, /g' | sed 's/, $//'
}
Names_display=$(get_Names_display)

function get_PolicyIDs() {
    /usr/libexec/PlistBuddy -c "Print :Applications" "$plistOutput" 2>/dev/null | \
    awk '/ID =/ {print $3}'
}

function GetPolicyName() {
    local policyID="$1"
    /usr/libexec/PlistBuddy -c "Print :Applications" "$plistOutput" 2>/dev/null | \
    awk -v searchID="$policyID" '
    BEGIN { found=0 }
    /ID = / {
        if ($3 == searchID) {
            found=1
        } else {
            found=0
        }
    }
    /Name =/ {
        if (found == 1) {
            sub(/^.*Name = */, "", $0)
            sub(/^ */, "", $0)
            print $0
            exit
        }
    }
'
}


    function UpdateJSONConfiguration() {
        # Zählt Hintergrund-Updates und speichert die Namen der in den Hintergrund aktualisierten Apps
        Update_Count_in_background=0
        updatedApps=()
        PolicyNameUserPromt=()
        
        # Lese den Wert für Update_Count aus der plist-Datei
        Update_Count=$(/usr/libexec/PlistBuddy -c "Print :ApplicationCount" "$plistOutput" 2>/dev/null)
        
        # Ermittele die IDs
        IDs=($(get_PolicyIDs))
        
        # JSON-Grundgerüst
        policyJSON='{"steps": ['
        
        # separater Zähler für hinzugefügte JSON-Objekte
        addedObjects=0
        
        for (( i = 0; i < ${#IDs[@]}; i++ )); do
            
            # Policy-ID und -Name
            PolicyID="${IDs[i]}"
            PolicyName="$(GetPolicyName "${PolicyID}")"
            
            # Case-Block für Icon, Validation und BundleID
            local icon validation BundelID
            case "$PolicyName" in
                *Google_Chrome* | *Chrome*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_94f8d7f60fe82fb234065e05cccf385b1a4f9763ea1b4a3d9737e6a980fd0eae"
                    validation="/Applications/Google Chrome.app/Contents/Info.plist"
                    BundelID="com.google.Chrome"
                ;;
                *Microsoft_Outlook* | *Outlook*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_b96ae8bdcb09597bff8b2e82ec3b64d0a2d17f33414dbd7d9a48e5186de7fd93"
                    validation="/Applications/Microsoft Outlook.app/Contents/Info.plist"
                    BundelID="com.microsoft.Outlook"
                ;;
                *Slack*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_a1ecbe1a4418113177cc061def4996d20a01a1e9b9adf9517899fcca31f3c026"
                    validation="/Applications/Slack.app/Contents/Info.plist"
                    BundelID="com.tinyspeck.slackmacgap"
                ;;
                *Company_Portal* | *Company\ Portal*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_2af383e90f870e948ec2d03a5910af1b27fe2b32d7c757848db0fdecfea2ef71"
                    validation="/Applications/Company Portal.app/Contents/Info.plist"
                    BundelID="com.microsoft.intune.companyportal"
                ;;
                *Mozilla_Firefox* | *Firefox*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_b50bdee2e72b3f98cd7cfe8da06a3d5f405507ca0dca2f5f408978f4f24fee0c"
                    validation="/Applications/Firefox.app/Contents/Info.plist"
                    BundelID="org.mozilla.firefox"
                ;;
                *GitHub_Desktop* | *GitHub\ Desktop*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_e7790b367556baee89ffb70d7d545b4cf78698e84cf646777a7d9058762bf69d"
                    validation="/Applications/GitHub Desktop.app/Contents/Info.plist"
                    BundelID="com.github.GitHubClient"
                ;;
                *iTerm2*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_85951b4b7b290fa90d8b3a4d7b652316acb5dac44ebce95e7a00a38879710cc6"
                    validation="/Applications/iTerm.app/Contents/Info.plist"
                    BundelID="com.googlecode.iterm2"
                ;;
                *Microsoft_Edge* | *Microsoft\ Edge* | *Edge*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_f1fa00c7d8b4cb4d3c58d98c0b0bdbe719a56be39f8b6445ed3df9c8219a126d"
                    validation="/Applications/Microsoft Edge.app/Contents/Info.plist"
                    BundelID="com.microsoft.edgemac"
                ;;
                *Microsoft_Excel* | *Microsoft\ Excel* | *Excel*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_721a7bf38cec7552ecd6ffaee9a0ed2ab21b2318639c23082250be12517fca1c"
                    validation="/Applications/Microsoft Excel.app/Contents/Info.plist"
                    BundelID="com.microsoft.Excel"
                ;;
                *Microsoft_OneNote* | *Microsoft\ OneNote* | *OneNote*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_a10ac257accff5479d467cf0c8f148559b92eb0ccb7c78f80464901532c95bdb"
                    validation="/Applications/Microsoft OneNote.app/Contents/Info.plist"
                    BundelID="com.microsoft.onenote.mac"
                ;;
                *Microsoft_PowerPoint* | *Microsoft\ PowerPoint* | *PowerPoint*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_9f13ca0d3ab7939d3147fbdea116fbdd94f6716a27292505231a8e93f6307fd6"
                    validation="/Applications/Microsoft PowerPoint.app/Contents/Info.plist"
                    BundelID="com.microsoft.Powerpoint"
                ;;
                *Microsoft_Remote_Desktop* | *Microsoft\ Remote\ Desktop*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_accfb8273af78d6e2f456a9e3ea882267f82e99c13f9e515d374ffd749aba082"
                    validation="/Applications/Microsoft Remote Desktop.app/Contents/Info.plist"
                    BundelID="com.microsoft.rdc.mac"
                ;;
                *Microsoft_Teams* | *Microsoft\ Teams* | *Teams*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_623505d45ca9c2a1bd26f733306e30cd3fcc1cc0fd59ffc89ee0bfcbfbd0b37e"
                    validation="/Applications/Microsoft Teams.app/Contents/Info.plist"
                    BundelID="com.microsoft.teams"
                ;;
                *Microsoft_Word* | *Word*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_a4686ab0e2efa2b3c30c42289e3958e5925b60b227ecd688f986d199443cc7a7"
                    validation="/Applications/Microsoft Word.app/Contents/Info.plist"
                    BundelID="com.microsoft.Word"
                    #BundelID=""
                ;;
                *Postman*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_019df97f436478ca2b98e3f858eb95d4a527a353029df0384f5b8f18dbd0c61d"
                    validation="/Applications/Postman.app/Contents/Info.plist"
                    #BundelID="com.postmanlabs.mac"
                    BundelID=""
                ;;
                *Support_App* | *Support\ App*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_6a2b5ed3a7762b7641b837fd5cc0a5541462f27ec43126db2d4e8dbdcc298f6d"
                    validation="/Applications/Support.app/Contents/Info.plist"
                    BundelID=""
                ;;
                *TeamViewer* | *Teamviewer*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_ccbb12778c38f0e2c245a712e78d417930c5d599f44832be9bbee1705f69d3e4"
                    validation="/Applications/TeamViewer.app/Contents/Info.plist"
                    BundelID="com.teamviewer.TeamViewer"
                ;;
                *Visual_Studio_Code* | *Visual\ Studio\ Code*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_011955c4065d9215a82905984bd200f224c8b3736e3fb947ba64b6fa28b0c02a"
                    validation="/Applications/Visual Studio Code.app/Contents/Info.plist"
                    BundelID="com.microsoft.VSCode"
                ;;
                *Zoom*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_92b8d3c448e7d773457532f0478a428a0662f694fbbfc6cb69e1fab5ff106d97"
                    validation="/Applications/zoom.us.app/Contents/Info.plist"
                    BundelID="us.zoom.xos"
                ;;
                *Zeplin*)
                    icon="https://euc1.ics.services.jamfcloud.com/icon/hash_8d184c2fc82089ed7790429560eee153f79795076999a6d2eef2d9ebcfc9b8d9"
                    validation="/Applications/Zeplin.app/Contents/Info.plist"
                    BundelID="io.zeplin.osx"
                ;;
                *VLC*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_2b428c169b78204f03cff3b040b2b5c428eac9288108e11d43aca994d5bd39f0"
                    validation="/Applications/VLC.app/Contents/Info.plist"
                    BundelID="org.videolan.vlc"
                ;;
                *The_Unarchiver* | *The\ Unarchiver*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_5ef15847e6f8b29cedf4e97a468d0cb1b67ec1dcef668d4493bf6537467a02c2"
                    validation="/Applications/The Unarchiver.app/Contents/Info.plist"
                    BundelID="cx.c3.theunarchiver"
                ;;
                *Sketch*)
                    icon="https://euc1.ics.services.jamfcloud.com/icon/hash_32f378b2490f45b03042fc8a388dbc433e7e2e4c2c68b697e3c9647fcd217e44"
                    validation="/Applications/Sketch.app/Contents/Info.plist"
                    BundelID="com.bohemiancoding.sketch3"
                ;;
                *Miro*)
                    icon="https://euc1.ics.services.jamfcloud.com/icon/hash_89d42f52cebdbb0862c2229254074da1b31dc334c984031a6ccfc5f46141a569"
                    validation="/Applications/Miro.app/Contents/Info.plist"
                    BundelID="com.electron.miro"
                ;;
                *Microsoft_Skype_for_Busines* | *Microsoft\ Skype\ for\ Busines* | *Skype\ for\ Busines*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_a0bb8ab7d90a958892febf03aea84f3b090c2dc0ea9305f7d17f27d622bfbb9e"
                    validation="/Applications/Skype for Business.app/Contents/Info.plist"
                    BundelID="com.microsoft.SkypeForBusiness"
                ;;
                *Keka*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_b2f82bb89f6e69834dec02b0f12ce6180fbdc1352494adf10d7e7a7aa65c85e6"
                    validation="/Applications/Keka.app/Contents/Info.plist"
                    BundelID="com.aone.keka"
                ;;
                *ImageOptim*)
                    icon="https://euc1.ics.services.jamfcloud.com/icon/hash_5dcd3a597ee4fd5b52e63ee0e5f86d97352d281398ee4e91d45abc75e292e086"
                    validation="/Applications/ImageOptim.app/Contents/Info.plist"
                    BundelID="net.pornel.ImageOptim"
                ;;
                *Filezilla*)
                    icon="https://euc1.ics.services.jamfcloud.com/icon/hash_b2aa33567e5b48be41e5165c6f02eac485710e041367a685be5bbc97b265229b"
                    validation="/Applications/FileZilla.app/Contents/Info.plist"
                    BundelID="org.filezilla-project.filezilla"
                ;;
                *DropBox*)
                    icon="https://euc1.ics.services.jamfcloud.com/icon/hash_e6361d9d6f2867bf1f939fb9fbe5b7f785413b17dd9d36331e02c3f42f1a3a07"
                    validation="/Applications/Dropbox.app/Contents/Info.plist"
                    BundelID="com.getdropbox.dropbox"
                ;;
                *Figma*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_ad7d074540cf041f9d9857ecf6c0223e38fb8e582168484b97ae95bd7b5a53de"
                    validation="/Applications/Figma.app/Contents/Info.plist"
                    BundelID="com.figma.Desktop"
                ;;
                *EasyFind*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_a7ad6e3e43ee50fcb73d3e26fd29146906681a6f048a3d305b4857f3165298f5"
                    validation="/Applications/EasyFind.app/Contents/Info.plist"
                    BundelID="com.devon-technologies.easyfind"
                ;;
                *DisplayLink_Manager* | *DisplayLink\ Manager*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_ed6f88bfb07d71e245f6b3d69574467f7089ef39d9a98f5d5d770b314706b460"
                    validation="/Applications/DisplayLink Manager.app/Contents/Info.plist"
                    BundelID="com.displaylink.displaylinkmanager"
                ;;
                *Cyberduck*)
                    icon="https://euc1.ics.services.jamfcloud.com/icon/hash_d807ad9581dffc5e7317c5b301104a43b37ceca866b36799053412ef327264b8"
                    validation="/Applications/Cyberduck.app/Contents/Info.plist"
                    BundelID="ch.sudo.cyberduck"
                ;;
                *Blender*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_d1420bec7e93fc1197c999f499ff1743764ac17789bee60f5466569e83fc7fab"
                    validation="/Applications/Blender.app/Contents/Info.plist"
                    BundelID="org.blenderfoundation.blender"
                ;;
                *Balsamiq_Wireframes* | *Balsamiq\ Wireframes*)
                    icon="https://euc1.ics.services.jamfcloud.com/icon/hash_2aacaa75080df809d095065d9fd5ac25066d1bfe90eec277f1834e82d44a555a"
                    validation="/Applications/Balsamiq Wireframes.app/Contents/Info.plist"
                    BundelID="com.balsamiq.mockups"  # possibly ‘com.balsamiq.mockups5’ or variant
                ;;
                *AppCleaner*)
                    icon="https://euc1.ics.services.jamfcloud.com/icon/hash_c304da7fe44e5ab4241d909a1051ae44e9af7d7694ed8dbc53f4d53e6dd0c1f6"
                    validation="/Applications/AppCleaner.app/Contents/Info.plist"
                    BundelID="net.freemacsoft.AppCleaner"
                ;;
                *Adobe_Creative_Cloud_Desktop* | *Adobe\ Creative\ Cloud\ Desktop*)
                    icon="$Adobe_Creative_Cloud_Desktop"
                    validation="$Adobe_Creative_Cloud_Desktop_validation"
                    # Frequently used IDs: com.adobe.acc.AdobeCreativeCloud or com.adobe.ccx.process
                    BundelID="com.adobe.acc.AdobeCreativeCloud"
                ;;
                *1Password_8* | *1Password\ 8* | *1Password*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_274cae31e3447da5b641ecd0dcd3ae6d27e7aa24e4aff112f54e9047f9711aa7"
                    validation="/Applications/1Password.app/Contents/Info.plist"
                    # Version 8: com.agilebits.onepassword8  (Attention: it may vary depending on the source of supply!)
                    BundelID="com.agilebits.onepassword8"
                ;;
                *Adobe_Acrobar_Reader* | *Adobe\ Acrobar\ Reader*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_d5f7f524284ff4ab5671cd5c92ef3938eea192ca4089e0c8b2692f49c5cfe47c"
                    validation="/Applications/Adobe Acrobat Reader.app/Contents/Info.plist"
                    BundelID="com.adobe.Reader"
                ;;
                *Anydesk*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_753118b231372bdecc36d637d85c1ebc65e306f341a6d18df4adef72a60aae8d"
                    validation="/Applications/AnyDesk.app/Contents/Info.plist"
                    BundelID="com.philandro.anydesk"
                ;;
                *Audacity*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_48856b6517bf045e425982abe4d4d036ba8d64ec4f83344cec88f19d3644053f"
                    validation="/Applications/Audacity.app/Contents/Info.plist"
                    BundelID="org.audacityteam.audacity"
                ;;
                *balenaEtcher* | *balena\ Etcher*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_c55e8e1eb9cdf4935385f77f2440784d28a111df750b9661c7cf20ec4806df3d"
                    validation="/Applications/balenaEtcher.app/Contents/Info.plist"
                    BundelID="com.balena.etcher"
                ;;
                *Clipy*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_69311ae3c55874b8c4a75698ea955d2be8169c132303b267de7c2610a5691946"
                    validation="/Applications/Clipy.app/Contents/Info.plist"
                    BundelID="com.clipy-app.Clipy"
                ;;
                *Drawio* | *Draw.io*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_fe1fe76b17903b7bdde014647234bc1afab379f375d61ef3844bfeca5f60cd74"
                    validation="/Applications/draw.io.app/Contents/Info.plist"
                    BundelID="com.jgraph.drawio.desktop"
                ;;
                *Keeping_you_Awake* | *Keeping\ you\ Awake*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_01bb3a85ce1165f3a6284dd032271778ca3b89380187ab1729188ad625e4d1ca"
                    validation="/Applications/KeepingYouAwake.app/Contents/Info.plist"
                    BundelID="info.marcel-dierkes.KeepingYouAwake"
                ;;
                *Monitor_Control* | *Monitor\ Control*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_09cfa66f17687de4177ec619924110cb0985da70c9ccfcba47944c59c65d4ea2"
                    validation="/Applications/MonitorControl.app/Contents/Info.plist"
                    BundelID="me.guillaumeb.MonitorControl"
                ;;
                *OmniGraffle_7* | *OmniGraffle\ 7* | *Omni\ Graffle\ 7* | *Omni\ Graffle*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_af797387cce835f0c01b4514c78b7a87e7889a272ad7ed5a100ec6f82661fe94"
                    validation="/Applications/OmniGraffle.app/Contents/Info.plist"
                    BundelID="com.omnigroup.OmniGraffle7"
                ;;
                *Rectangle*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_656b155e64d443182726fe264ac2d7d31295ec7529b5f28afcd04eb1599c9253"
                    validation="/Applications/Rectangle.app/Contents/Info.plist"
                    BundelID="com.knollsoft.Rectangle"
                ;;
                *Sourcetree*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_176409e6a4b5ca1bc4cf2b0b98e03a87701adf56a1cf64121284786e30e4721f"
                    validation="/Applications/Sourcetree.app/Contents/Info.plist"
                    BundelID="com.torusknot.SourceTreeNotMAS"
                ;;
                *Zulip*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_4ae4efbb4993900bbac7b3fc0e298e804b37730e0e83f1ccb1dbf4fd79bb1c8e"
                    validation="/Applications/Zulip.app/Contents/Info.plist"
                    BundelID="org.zulip.zulip"
                ;;
                *Go_to_Meeting* | *Go\ to\ Meeting*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_03e38ad91467fca7875becc5cec5141358ac013cb0ead27145653673324efb0a"
                    validation="/Applications/GoToMeeting.app/Contents/Info.plist"
                    BundelID="com.logmein.GoToMeeting"
                ;;
                *GIMP*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_db1f5181e6c32c57e0d7e777fa392c870552172ac5c5316a0618f94b4ebd1a94"
                    validation="/Applications/GIMP.app/Contents/Info.plist"
                    BundelID="org.gimp.GIMP"
                ;;
                *Apache_Directory_Studio* | *Apache\ Directory\ Studio*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_5497c297450e6e5a60a1ed540e82759c1c41d9b8c3e0774f8805b8f8e78101fe"
                    validation="/Applications/ApacheDirectoryStudio.app/Contents/Info.plist"
                    BundelID="org.apache.directory.studio"
                ;;
                *Azure_Data_Studio* | *Azure\ Data\ Studio*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_967faf08185090d670b1fbaeec5243431d5ccadd508abbae5f4cbd9279876a6c"
                    validation="/Applications/Azure Data Studio.app/Contents/Info.plist"
                    BundelID="com.microsoft.azuredatastudio"
                ;;
                *Docker*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_34da3317712f203f9d80ce968304d0a490900e68ab7986a79c4a290f4d63a9af"
                    validation="/Applications/Docker.app/Contents/Info.plist"
                    BundelID="com.docker.docker"
                ;;
                *Meld*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_7635c2f1f8439aa3b129a9db0755dae6a0d76f141e1afa2252e0020f5214ee8e"
                    validation="/Applications/Meld.app/Contents/Info.plist"
                    BundelID="org.gnome.meld"
                ;;
                *PyCharm*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_3f93975114b0199f0bd1baf116db1549f87f5b0165f03df5014edda3ff365f7a"
                    validation="/Applications/PyCharm.app/Contents/Info.plist"
                    BundelID="com.jetbrains.pycharm"
                ;;
                *SquidMan* | *Squid\ Man*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_a89c20c9145dfa733c425e7c121e503ed270348ffcce255f4837aca001949dab"
                    validation="/Applications/SquidMan.app/Contents/Info.plist"
                    BundelID="it.antonioventuri.squidman"
                ;;
                *TNEFs_Enough* | *TNEFs\ Enough*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_302941a1fa63b8289b2bbabfdddb7056d67f83e8913d234c1833e15e3a012602"
                    validation="/Applications/TNEF's Enough.app/Contents/Info.plist"
                    # In some cases ‘com.joshjacob.tnef’, but not consistently confirmed
                    BundelID="com.joshjacob.tnef"
                ;;
                *Wireshark*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_1f874fcf121ba5028ee8740a8478fda171fe85d778fda72b93212af78290f8f3"
                    validation="/Applications/Wireshark.app/Contents/Info.plist"
                    BundelID="org.wireshark.Wireshark"
                ;;
                *Jabra_Direct* | *Jabra\ Direct*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_7207235148a8c306ac40e3248dfa7e74ccbb912562ab2b18d98d151a35e038c2"
                    validation="/Applications/Jabra Direct.app/Contents/Info.plist"
                    # Not 100% confirmed, leave blank if unknown
                    BundelID=""
                ;;
                *SimpleMind_Pro* | *SimpleMind\ Pro* | *Simple\ Mind\ Pro*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_d23a5a8752af9e4de9b960850118ef8f85cd5ae4c742ff7f839792f795153f04"
                    validation="/Applications/SimpleMind Pro.app/Contents/Info.plist"
                    # For some versions: ‘com.modelmakertools.simplemindmac’
                    BundelID="com.modelmakertools.simplemindmac"
                ;;
                *Tunnelblick*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_0ff661450177e85368cc22c97703c73d2e13b161e7289c440faeafcea0389bfd"
                    validation="/Applications/Tunnelblick.app/Contents/Info.plist"
                    BundelID="net.tunnelblick.tunnelblick"
                ;;
                *UTM*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_d51d14a3397054293dd5591df171a6f37825093f89dbe8f03191fd024e0c0ddc"
                    validation="/Applications/UTM.app/Contents/Info.plist"
                    BundelID="com.utmapp.UTM"
                ;;
                *Bitwarden*)
                    icon="https://ics.services.jamfcloud.com/icon/hash_4eb5da16820a8d37cc5918213323b5d2ae2bdb1cfed104d84535299123acab18"
                    validation="/Applications/Bitwarden.app/Contents/Info.plist"
                    BundelID="com.bitwarden.desktop"
                ;;
                *Brave*)
                    icon="https://euc1.ics.services.jamfcloud.com/icon/hash_d07ef04ebf5d9a509070858a26c39fd99feef114422de934973b6b19cb565a6c"
                    validation="/Applications/Brave Browser.app/Contents/Info.plist"
                    BundelID="com.brave.Browser"
                ;;
                *Jamf_Connect* | *Jamf\ Connect*)
                    icon="https://euc1.ics.services.jamfcloud.com/icon/hash_c7473f7ba3d046e0937dc9ad2fa1bc1453661d1303cd17693e5973948bb4a167"
                    validation="/Applications/Jamf Connect.app/Contents/Info.plist"
                    BundelID=""
                ;;
                *)
                    icon="https://ics.services.jamfcloud.com/icon/hash_ff2147a6c09f5ef73d1c4406d00346811a9c64c0b6b7f36eb52fcb44943d26f9"
                    validation="None"
                    BundelID=""
                ;;
            esac
            
            # Prüfen, ob BundelID leer ist
            if [[ -z "$BundelID" ]]; then
                # Keine BundleID => direkt in JSON einfügen
                if (( addedObjects > 0 )); then
                    policyJSON+=','
                fi
                policyJSON+='{
                "listitem": "'"${PolicyName}"'",
                "icon": "'"${icon}"'",
                "progresstext": "Updating '"${PolicyName}"'",
                "trigger_list": [
                    {
                        "trigger": "'"${PolicyID}"'",
                        "validation": "'"${validation}"'"
                    }
                ]
            }'
                (( addedObjects++ ))
                PolicyNameUserPromt+=( "$PolicyName" )
            else
                # BundleID vorhanden => Service-Check
                result=$(/bin/launchctl asuser "$loggedInUserID" sudo -iu "$loggedInUser" /bin/launchctl list 2>/dev/null | grep -F "$BundelID")
                
                if [[ -z "$result" ]]; then
                    # Service läuft nicht => jamf Policy ausführen
                    updateScriptLog "BACKGROUND-UPDATER: The application: $PolicyName is not executed. The policy with the trigger: ${PolicyID} is now executed."
                    /usr/local/bin/jamf policy -id "${PolicyID}" -forceNoRecon
                    
                    (( Update_Count-- ))
                    (( Update_Count_in_background++ ))
                    updatedApps+=( "$PolicyName" )
                    
                    # Falls Update_Count == 0, Recon ausführen und Skript beenden
                    if [[ $Update_Count -eq 0 ]]; then
                        updateScriptLog "BACKGROUND-UPDATER: All applications could be executed in the background. The inventory is transferred to Jamf and the script is terminated without user information."
                        updateScriptLog "BACKGROUND-UPDATER: The following applications have been updated: ${updatedApps[*]}"
                        /usr/local/bin/jamf recon
                        
                        if [[ "$LaunchDaemonisReady" -eq 1 ]]; then
                            updateScriptLog "Remove existing LaunchDaemon (since updates were successful)."
                            ClearUpPlist
                            ClearUpLaunchDaemon
                        fi
                        
                        exit 0
                    fi
                else
                    # Service läuft => in JSON einfügen
                    if (( addedObjects > 0 )); then
                        policyJSON+=','
                    fi
                    policyJSON+='{
                    "listitem": "'"${PolicyName}"'",
                    "icon": "'"${icon}"'",
                    "progresstext": "Updating '"${PolicyName}"'",
                    "trigger_list": [
                        {
                            "trigger": "'"${PolicyID}"'",
                            "validation": "'"${validation}"'"
                        }
                    ]
                }'
                    (( addedObjects++ ))
                    PolicyNameUserPromt+=( "$PolicyName" )
                fi
            fi
            
        done
        
        # Logge verbleibende Updates
        updateScriptLog "BACKGROUND-CHECK: Remaining updates that could not be updated in the background: $Update_Count"
        
        # Inventory-Eintrag am Ende anhängen
        if (( addedObjects > 0 )); then
            policyJSON+=','
        fi
        policyJSON+='{
        "listitem": "Update Inventory",
        "icon": "https://ics.services.jamfcloud.com/icon/hash_ff2147a6c09f5ef73d1c4406d00346811a9c64c0b6b7f36eb52fcb44943d26f9",
        "progresstext": "Updating Inventory",
        "trigger_list": [
            {
                "trigger": "recon",
                "validation": "None"
            }
        ]
    }]
    }'
        
        if (( Update_Count_in_background > 0 )); then
            updateScriptLog "BACKGROUND-CHECK: The following number of applications could be updated in the background: $Update_Count_in_background"
            updateScriptLog "BACKGROUND-CHECK: The following applications have been updated: ${updatedApps[*]}"
        else
            updateScriptLog "BACKGROUND-CHECK: No applications could be updated in the background"
        fi
        
        if (( ${#PolicyNameUserPromt[@]} > 0 )); then
            joinedPolicyNames=$(IFS=", ' '"; echo "${PolicyNameUserPromt[*]}")
            updateScriptLog "BACKGROUND-CHECK: The following applications could not be updated in the background: $joinedPolicyNames"
        fi
    }

UpdateJSONConfiguration

echo $policyJSON

if [[ "$Update_Count" -eq 1 ]]
then
    Plural_EN=""
    Plural_DE=""
    pluralQuantity_DE="ist"
else
    Plural_EN="s"
    Plural_DE="s"
    pluralQuantity_DE="sind"
fi

Plural=Plural_${UserLanguage}

if [[ "$Update_Count" -eq 1 ]]
then
    final_sucess_progresstext_EN="The update has been installed. Thanks for the patience ${loggedInUserFirstname}."
    final_sucess_progresstext_DE="Das Update wurde installiert. Danke für die Geduld ${loggedInUserFirstname}."
    
else
    final_sucess_progresstext_EN="All updates have been installed. Thanks for the patience ${loggedInUserFirstname}."
    final_sucess_progresstext_DE="Alle Updates wurden installiert. Danke für die Geduld ${loggedInUserFirstname}."
fi

# # # # # # # # # # # # # # # # # # # "Patch Helper" dialog Title, Messages # # # # # # # # # # # # # # # #
UserInfoTitle_DE="Hey ${loggedInUserFirstname}, es $pluralQuantity_DE ${Update_Count} Update${!Plural} verfügbar."
UserInfoTitle_EN="Hello ${loggedInUserFirstname}, there $pluralQuantity_EN ${Update_Count} update${!Plural} available."

# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
UserInfoMessage_DE="Die folgenden Programme werden aktualisiert: \n\n${joinedPolicyNames[*]} \n\n--- \nWährend der Installation werden sie geschlossen. Bitte klicke auf **Update**, um mit der Aktualisierung zu beginnen. \n\n#### Verbleibende Anzahl an Verschiebungen: $CurrentDeferralValue \n\nDieser Dialog wird Dich **${!Time}** erinnern, bis die maximale Verschiebung der Updates erreicht ist."

UserInfoMessage_EN="The following applications are updated: \n\n${joinedPolicyNames[*]} \n\n--- \nDuring the installation the affected applications will be closed. Please click **Update** to start the update. \n\n#### Remaining number of moves: $CurrentDeferralValue \n\nUnless you apply the updates, this dialog **${!Time}** will remind you until the number reaches **0**."
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
UserEnforceMessage_DE="**Hallo ${loggedInUserFirstname}, Deine Updates können nun nicht mehr verschoben werden.** \n Die folgenden Programme werden nun aktualisiert: \n\n${Names_display[*]} \n\n--- \nWährend der Installation werden die betroffenen Programme geschlossen. Bitte klicke nun auf **Update**."

UserEnforceMessage_EN="**Hello ${loggedInUserFirstname} you have moved as many times as possible.** \n The following applications will now be updated: \n\n${Names_display[*]} \n\n--- \nDuring the installation the affected applications will be closed. Please click on **Update** now."

# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
title_DE="Aktualisierung läuft....."
title_EN="Update in progress....."

# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
message_DE="Bitte warte, während die folgenden Anwendungen aktualisiert werden…"
message_EN="Please wait while the following applications are installed…"

# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
helpmessage_DE="Wenn Du Hilfe benötigst, wende Dich bitte an die Support Services:  \n- **Telefon:** ${Support_Telefon}  \n- **Email:** ${Support_Email} \n\n**Computer Information:** \n\n- **Betriebssystem:**  ${macOSproductVersion} ($macOSbuildVersion)  \n- **Seriennummer:** ${serialNumber}  \n- **Dialog:** ${dialogVersion}  \n- **Started:** ${timestamp}"

helpmessage_EN="If you need help, please contact Support Services:  \n- **Telephone:** ${Support_Telefon}  \n- **Email:** ${Support_Email} \n\n**Computer Information:** \n\n- **Operating System:**  ${macOSproductVersion} ($macOSbuildVersion)  \n- **Serial Number:** ${serialNumber}  \n- **Dialog:** ${dialogVersion}  \n- **Started:** ${timestamp}"

# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
failureTitle_DE="Fehler gefunden"
failureTitle_EN="Error found"

# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
final_sucess_titel_DE="Update Helper abgeschlossen"
final_sucess_titel_EN="Patch Helper completed"

# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
progresstext_DE="Initialisiere Patch Helper ..."
progresstext_EN="Initialization Patch Helper ..."

# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
button1text_DE="Bitte warten"
button1text_EN="Please wait"

failureMessage="Placeholder message; update in the 'finalise' function"
failureIcon="SF=xmark.circle.fill,weight=bold,colour1=#BB1717,colour2=#F31F1F"    
#overlayicon=$( defaults read /Library/Preferences/com.jamfsoftware.jamf.plist self_service_app_path 2>&1 )
overlayicon=$InfoboxIcon


infobox="Analyzing System …"

UserInfoTitle=UserInfoTitle_${UserLanguage}
UserInfoMessage=UserInfoMessage_${UserLanguage}
UserEnforceMessage=UserEnforceMessage_${UserLanguage}

title=title_${UserLanguage}
message=message_${UserLanguage}
helpmessage=helpmessage_${UserLanguage}
failureTitle=failureTitle_${UserLanguage}
final_error_titel=final_error_titel_${UserLanguage}
final_error_progresstext=final_error_progresstext_${UserLanguage}
final_sucess_titel=final_sucess_titel_${UserLanguage}
final_sucess_progresstext=final_sucess_progresstext_${UserLanguage}
progresstext=progresstext_${UserLanguage}
button1text=button1text_${UserLanguage}


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#
# PROMPT DIALOG
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# "Promt User for Updates" JSON
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
if [[ "$CurrentDeferralValue" -gt 0 ]]
then
    # Reduce the timer by 1. The script will run again the next day
    let CurrTimer=$CurrentDeferralValue-1
    setDeferral "$BundleID" "$DeferralType" "$CurrTimer" "$DeferralPlist"
    
    PromtUserJSON='
{
    "bannerimage" : "'${BannerImage}'",
    "title" : "'${!UserInfoTitle}'",
    "message" : "'${!UserInfoMessage}'",
    "icon" : "'${InfoboxIcon}'",
    "iconsize" : "198.0",
    "button1text" : "Update",
    "button2text" : "Later",
    "timer" : "'${TimePromtUser}'",
    "infotext" : "'${scriptVersion}'",
    "ontop" : "true",
    "titlefont" : "shadow=true, size=28",
    "messagefont" : "size=16",
    "width" : "700",
    "height" : "625"
}
'
else
    PromtUserJSON='
{
    "bannerimage" : "'${BannerImage}'",
    "title" : "'${!UserInfoTitle}'",
    "message" : "'${!UserEnforceMessage}'",
    "icon" : "'${InfoboxIcon}'",
    "iconsize" : "198.0",
    "button1text" : "Update",
    "infotext" : "'${scriptVersion}'",
    "ontop" : "true",
    "titlefont" : "shadow=true, size=28",
    "messagefont" : "size=16",
    "width" : "700",
    "height" : "625"
}
'
fi

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#
# Patch Helper dialog
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# "Patch Helper" dialog Title, Message, Icon and Overlay Icon
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
infobox="Analyzing input …"

# Set initial icon based on whether the Mac is a desktop or laptop
if system_profiler SPPowerDataType | grep -q "Battery Power"; then
    icon="SF=laptopcomputer.and.arrow.down,weight=semibold,colour1=#ffffff,colour2=#2986cc"
else
    icon="SF=desktopcomputer.and.arrow.down,weight=semibold,colour1=#ffffff,colour2=#2986cc"
fi

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# "Patch Helper" dialog Settings and Features
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
runUpdates="$dialogBinary \
--bannerimage \"$BannerImage\" \
--title \"${!title}\" \
--message \"${!message}\" \
--helpmessage \"${!helpmessage}\" \
--icon \"$icon\" \
--infobox \"${infobox}\" \
--progress \
--progresstext \"${!progresstext}\" \
--button1text \"${!button1text}\" \
--button1disabled \
--infotext \"$scriptVersion\" \
--titlefont 'shadow=true, size=28' \
--messagefont 'size=14' \
--width '700' \
--height '625' \
--position 'centre' \
--moveable \
--overlayicon \"$overlayicon\" \
--quitkey k \
--commandfile \"$PatchHelperCommandFile\" "


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#
# Failure dialog
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# "Failure" dialog Title, Message and Icon
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
failureMessage="Placeholder message; update in the 'finalise' function"
failureIcon="SF=xmark.circle.fill,weight=bold,colour1=#BB1717,colour2=#F31F1F"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# "Failure" dialog Settings and Features
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
dialogFailureCMD="$dialogBinary \
--moveable \
--title \"${!failureTitle}\" \
--message \"$failureMessage\" \
--icon \"$failureIcon\" \
--iconsize 125 \
--width 625 \
--height 525 \
--position topright \
--button1text \"Close\" \
--infotext \"$scriptVersion\" \
--titlefont 'size=22' \
--messagefont 'size=14' \
--overlayicon \"$overlayicon\" \
--commandfile \"$failureCommandFile\" "

#------------------------ With the execption of the `finalise` function, -------------------------#
#------------------------ edits below these line are optional. -----------------------------------#

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Dynamically set `button1text` based on the value of `completionActionOption`
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
case ${completionActionOption} in

    "Quit" )
        button1textCompletionActionOption="Quit"
        progressTextCompletionAction=""
        ;;

    * )
        button1textCompletionActionOption="Close"
        progressTextCompletionAction=""
        ;;

esac

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#
# Functions
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Run command as logged-in user (thanks, @scriptingosx!)
# shellcheck disable=SC2145
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
function runAsUser() {
    updateScriptLog "Run \"$@\" as \"$loggedInUserID\" … "
    launchctl asuser "$loggedInUserID" sudo -u "$loggedInUser" "$@"
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Update the "Welcome" dialog
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
function dialogPatchHelper(){
    updateScriptLog "PROMT USER DIALOG: $1"
    echo "$1" >> "$CommandFile"
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Update the "Patch Helper" dialog
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
function PatchHelper() {
    updateScriptLog "Patch Helper DIALOG: $1"
    echo "$1" >> "$PatchHelperCommandFile"
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Update the "Failure" dialog
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
function dialogUpdateFailure(){
    updateScriptLog "FAILURE DIALOG: $1"
    echo "$1" >> "$failureCommandFile"
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Finalise User Experience
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
function finalise(){
    
    # Output Line Number in `true` Debug Mode
    if [[ "${debugMode}" == "true" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi
    
    if [[ "${jamfProPolicyTriggerFailure}" == "failed" ]]; then
        
        
        killProcess "caffeinate"
        if [[ $Language = de* ]]
            then
                PatchHelper "title: Entschuldige ${loggedInUserFirstname}, etwas ist schiefgelaufen."
                PatchHelper "progresstext: Fehler erkannt. Bitte klicke auf Ok, um Informationen zur Fehlerbehebung zu erhalten."
            else
                PatchHelper "title: Sorry ${loggedInUserFirstname}, something went wrong."
                PatchHelper "progresstext: Error detected. Please click ok for troubleshooting information."
        fi
        
        PatchHelper "icon: SF=xmark.circle.fill,weight=bold,colour1=#BB1717,colour2=#F31F1F"
        PatchHelper "button1text: OK"
        PatchHelper "button1: enable"
        PatchHelper "progress: reset"
        
        
        # Wait for user-acknowledgment due to detected failure
        wait
        
        PatchHelper "quit:"
        eval "${dialogFailureCMD}" & sleep 0.3
        
        updateScriptLog "\n\n# # #\n# FAILURE DIALOG\n# # #\n"
        updateScriptLog "Jamf Pro Policy Name Failures:"
        updateScriptLog "${jamfProPolicyNameFailures}"
        
        if [[ $Language = de* ]]
        then
            dialogUpdateFailure "message: Es wurden Fehler festgestellt, ${loggedInUserFirstname}.  \n\nBei der Aktualisierung der Applikationen ist etwas schiefgelaufen.  \n\nFolgende Applikationen konnten nicht akualisiert werden:  \n${jamfProPolicyNameFailures}  \n\n\n\nWenn Du Hilfe benötigst, wenden Dich bitte an die Support Services unter \n${Support_Email} \n\nDu kannst  die Applikationen jederzeit aus dem Self Service wieder installieren."
        else
            dialogUpdateFailure "message: Errors were detected ${loggedInUserFirstname}.  \n\nPlease perform the following steps:\n1. Restart your Mac and log in again.  \n2. Start the Self Service \n3. Run all the failed policies listed below again \n\nThe following failed:  \n${jamfProPolicyNameFailures}  \n\n\nIf you need help, please contact the helpdesk, \n${Support_Email}"
        fi
            
        
        dialogUpdateFailure "icon: SF=xmark.circle.fill,weight=bold,colour1=#BB1717,colour2=#F31F1F"
        dialogUpdateFailure "button1text: ${button1textCompletionActionOption}"
        
        # Wait for user-acknowledgment due to detected failure
        wait
        
        dialogUpdateFailure "quit:"
        quitScript "1"
        
    else
        
        PatchHelper "title: ${!final_sucess_titel}"        
        PatchHelper "progresstext: ${!final_sucess_progresstext}"
        
        PatchHelper "icon: SF=checkmark.circle.fill,weight=bold,colour1=#00ff44,colour2=#075c1e"
        PatchHelper "progress: complete"
        PatchHelper "button1text: ${button1textCompletionActionOption}"
        PatchHelper "button1: enable"
        
        
        # If either "wait" or "sleep" has been specified for `completionActionOption`, honor that behavior
        if [[ "${completionActionOption}" == "wait" ]] || [[ "${completionActionOption}" == "[Ss]leep"* ]]; then
            updateScriptLog "Honoring ${completionActionOption} behavior …"
            eval "${completionActionOption}" "${PatchHelperProcessID}"
        fi
        
        quitScript "0"
        
    fi
    
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Parse JSON via osascript and JavaScript
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
function get_json_value() {
    JSON="$1" osascript -l 'JavaScript' \
        -e 'const env = $.NSProcessInfo.processInfo.environment.objectForKey("JSON").js' \
        -e "JSON.parse(env).$2"
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Parse JSON via osascript and JavaScript for the PROMT USER DIALOG
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
function get_json_value_UserInformation() {
    for var in "${@:2}"; do jsonkey="${jsonkey}['${var}']"; done
    JSON="$1" osascript -l 'JavaScript' \
        -e 'const env = $.NSProcessInfo.processInfo.environment.objectForKey("JSON").js' \
        -e "JSON.parse(env)$jsonkey"
}
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Execute Jamf Pro Policy Custom Events
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
function run_jamf_trigger() {

    # Output Line Number in `true` Debug Mode
    if [[ "${debugMode}" == "true" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi

    trigger="$1"

    if [[ "${debugMode}" == "true" ]]; then

        updateScriptLog "Patch Helper DIALOG: DEBUG MODE: TRIGGER: $jamfBinary policy -id $trigger"
        if [[ "$trigger" == "recon" ]]; then
            updateScriptLog "Patch Helper DIALOG: DEBUG MODE: RECON: $jamfBinary recon ${reconOptions}"
        fi
        sleep 1

    elif [[ "$trigger" == "recon" ]]; then

        PatchHelper "listitem: index: $i, status: wait, statustext: Updating …, "
        updateScriptLog "Patch Helper DIALOG: Computer inventory, with the following reconOptions: \"${reconOptions}\", will be be executed in the 'confirmPolicyExecution' function …"
        # eval "${jamfBinary} recon ${reconOptions}"
    else
        updateScriptLog "Patch Helper DIALOG: RUNNING: $jamfBinary policy -id $trigger -forceNoRecon"
        eval "${jamfBinary} policy -id ${trigger}"                                     # Add comment for policy testing
        # eval "${jamfBinary} policy -id ${trigger} -true | tee -a ${scriptLog}"    # Remove comment for policy testing
    fi

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Confirm Policy Execution
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function confirmPolicyExecution() {

    # Output Line Number in `true` Debug Mode
    if [[ "${debugMode}" == "true" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi

    trigger="${1}"
    validation="${2}"
    updateScriptLog "Patch Helper DIALOG: Confirm Policy Execution: '${trigger}' '${validation}'"

    case ${validation} in

        */* ) # If the validation variable contains a forward slash (i.e., "/"), presume it's a path and check if that path exists on disk
            if [[ "${debugMode}" == "true" ]]; then
                updateScriptLog "Patch Helper DIALOG: Confirm Policy Execution: DEBUG MODE: Skipping 'run_jamf_trigger ${trigger}'"
                sleep 1
            elif [[ -f "${validation}" ]]; then
                updateScriptLog "Patch Helper DIALOG: Confirm Policy Execution: ${validation} exist; executing 'run_jamf_trigger ${trigger}'"
                
                run_jamf_trigger "${trigger}"
                    if [[ -f "${validation}" ]] ; then
                        
                        updateScriptLog "Patch Helper DIALOG: Confirm Policy Execution: ${validation} exist"
                    
                    fi
                                
            else
                updateScriptLog "Patch Helper DIALOG: Confirm Policy Execution: ${validation} does NOT exist; executing 'run_jamf_trigger ${trigger}'"
                
                run_jamf_trigger "${trigger}"
            fi
        ;;

        "None" )
            updateScriptLog "Patch Helper DIALOG: Confirm Policy Execution: ${validation}"
            if [[ "${debugMode}" == "true" ]]; then
                sleep 5
            else
                run_jamf_trigger "${trigger}"
            fi
            ;;

        * )
            updateScriptLog "Patch Helper DIALOG: Confirm Policy Execution Catch-all: ${validation}"
            if [[ "${debugMode}" == "true" ]] 
                then
                    sleep 1
                else
                    run_jamf_trigger "${trigger}"
            fi
            ;;
    esac
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Validate Policy Result
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function validatePolicyResult() {
    
    # Output Line Number in `true` Debug Mode
    if [[ "${debugMode}" == "true" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi
    
    trigger="${1}"
    validation="${2}"
    updateScriptLog "Patch Helper DIALOG: Validate Policy Result: '${trigger}' '${validation}'"
    
    case ${validation} in
        
        ###
        # Absolute Path
        # Simulates pre-v1.6.0 behavior, for example: "/Applications/Microsoft Teams.app/Contents/Info.plist"
        ###
        
        */* ) 
            updateScriptLog "Patch Helper DIALOG: Validate Policy Result: Testing for \"$validation\" …"
            if [[ -f "${validation}" ]]
                then
                    PatchHelper "listitem: index: $i, status: success, statustext: Installed"
                else
                    PatchHelper "listitem: index: $i, status: fail, statustext: Failed"
                    jamfProPolicyTriggerFailure="failed"
                    exitCode="1"
                    jamfProPolicyNameFailures+="• $listitem  \n"
            fi
        ;;
        
        ###
        # Local
        # Validation within this script, for example: "rosetta" or "filevault"
        ###
        
        "Local" )
            case ${trigger} in
                rosetta ) 
                    updateScriptLog "Patch Helper DIALOG: Locally Validate Policy Result: Rosetta 2 … "
                    PatchHelper "listitem: index: $i, status: wait, statustext: Checking …"
                    arch=$( /usr/bin/arch )
                    if [[ "${arch}" == "arm64" ]]; then
                        # Mac with Apple silicon; check for Rosetta
                        rosettaTest=$( arch -x86_64 /usr/bin/true 2> /dev/null ; echo $? )
                        if [[ "${rosettaTest}" -eq 0 ]]; then
                            # Installed
                            updateScriptLog "Patch Helper DIALOG: Locally Validate Policy Result: Rosetta 2 is installed"
                            PatchHelper "listitem: index: $i, status: success, statustext: Running"
                        else
                            # Not Installed
                            updateScriptLog "Patch Helper DIALOG: Locally Validate Policy Result: Rosetta 2 is NOT installed"
                            PatchHelper "listitem: index: $i, status: fail, statustext: Failed"
                            jamfProPolicyTriggerFailure="failed"
                            exitCode="1"
                            jamfProPolicyNameFailures+="• $listitem  \n"
                        fi
                    else
                        # Inelligible
                        updateScriptLog "Patch Helper DIALOG: Locally Validate Policy Result: Rosetta 2 is not applicable"
                        PatchHelper "listitem: index: $i, status: success, statustext: not needed"
                    fi
                ;;
                * )
                    updateScriptLog "Patch Helper DIALOG: Locally Validate Policy Results Local Catch-all: ${validation}"
                ;;
            esac
        ;;
                
        "None" )
            # Output Line Number in `true` Debug Mode
            if [[ "${debugMode}" == "true" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi
            updateScriptLog "Patch Helper DIALOG: Confirm Policy Execution: ${validation}"
            PatchHelper "listitem: index: $i, status: success, statustext: Installed"
            if [[ "${trigger}" == "recon" ]]; then
                PatchHelper "listitem: index: $i, status: wait, statustext: Updating …, "
                updateScriptLog "Patch Helper DIALOG: Updating computer inventory with the following reconOptions: \"${reconOptions}\" …"
                if [[ "${debugMode}" == "true" ]]; then
                    updateScriptLog "Patch Helper DIALOG: DEBUG MODE: eval ${jamfBinary} recon ${reconOptions}"
                else
                    eval "${jamfBinary} recon ${reconOptions}"
                fi
                PatchHelper "listitem: index: $i, status: success, statustext: Updated"
            fi
        ;;
        
        ###
        # Catch-all
        ###
        
        * )
            # Output Line Number in `true` Debug Mode
            if [[ "${debugMode}" == "true" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi
            updateScriptLog "Patch Helper DIALOG: Validate Policy Results Catch-all: ${validation}"
            PatchHelper "listitem: index: $i, status: error, statustext: Error"
        ;;
    esac
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Kill a specified process
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
function killProcess() {
    process="$1"
    if process_pid=$( pgrep -a "${process}" 2>/dev/null ) ; then
        updateScriptLog "Attempting to terminate the '$process' process …"
        updateScriptLog "(Termination message indicates success.)"
        kill "$process_pid" 2> /dev/null
        if pgrep -a "$process" >/dev/null ; then
            updateScriptLog "ERROR: '$process' could not be terminated."
        fi
    else
        updateScriptLog "QUIT SCRIPT: The '$process' process isn't running."
    fi
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Completion Action (i.e., Wait, Sleep, Logout, Restart or Shutdown)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
function completionAction() {

    # Output Line Number in `true` Debug Mode
    if [[ "${debugMode}" == "true" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi

    if [[ "${debugMode}" == "true" ]]; then

        # If Debug Mode is enabled, ignore specified `completionActionOption`, display simple dialog box and exit
        runAsUser osascript -e 'display dialog "Patch Helper is operating in Debug Mode.\r\r• completionActionOption == '"'${completionActionOption}'"'\r\r" with title "Patch Helper: Debug Mode" buttons {"Close"} with icon note'
        exitCode="0"

    else

        shopt -s nocasematch

        case ${completionActionOption} in

            "Quit" )
                updateScriptLog "Quitting script"
                exitCode="0"
                ;;

            * )
                updateScriptLog "Using the default of 'wait'"
                wait
                ;;

        esac

        shopt -u nocasematch
    fi
    exit "${exitCode}"
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Quit Script
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function quitScript() {

    # Output Line Number in `true` Debug Mode
    if [[ "${debugMode}" == "true" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi

    updateScriptLog "QUIT SCRIPT: Exiting …"
    updateScriptLog "QUIT SCRIPT: Revoke API Token"
    invalidateToken
    # Stop `caffeinate` process
    updateScriptLog "QUIT SCRIPT: De-caffeinate …"
    killProcess "caffeinate"

    # Remove overlayicon
    if [[ -e ${overlayicon} ]]; then
        updateScriptLog "QUIT SCRIPT: Removing ${overlayicon} …"
        rm "${overlayicon}"
    fi
    
    # Remove CommandFile
    if [[ -e ${CommandFile} ]]; then
        updateScriptLog "QUIT SCRIPT: Removing ${CommandFile} …"
        rm "${CommandFile}"
    fi

    # Remove PatchHelperCommandFile
    if [[ -e ${PatchHelperCommandFile} ]]; then
        updateScriptLog "QUIT SCRIPT: Removing ${PatchHelperCommandFile} …"
        rm "${PatchHelperCommandFile}"
    fi

    # Remove failureCommandFile
    if [[ -e ${failureCommandFile} ]]; then
        updateScriptLog "QUIT SCRIPT: Removing ${failureCommandFile} …"
        rm "${failureCommandFile}"
    fi

    # Remove any default dialog file
    if [[ -e /var/tmp/dialog.log ]]; then
        updateScriptLog "QUIT SCRIPT: Removing /var/tmp/dialog.log"
        rm /var/tmp/dialog.log
    fi

    # Remove tmp files
    if [[ -e ${plistOutput} ]]; then
        updateScriptLog "QUIT SCRIPT: Removing ${plistOutput} …"
        rm "${plistOutput}"
    fi
    
    if [[ -e ${xmlupdates} ]]; then
        updateScriptLog "QUIT SCRIPT: Removing ${xmlupdates} …"
        rm "${xmlupdates}"
    fi
    
    if [[ "$ClearUpDeferral" == "true" ]]; then
        updateScriptLog "QUIT SCRIPT: Removing LaunchDaemon …"
        ClearUpDeferral
    fi
    
    # Check for user clicking "Quit" at PROMT USER DIALOG
    if [[ "${PromtUser}" == "2" ]]; then
        exitCode="0"
        exit "${exitCode}"
    else
        updateScriptLog "QUIT SCRIPT: Executing Completion Action Option: '${completionActionOption}' …"
        completionAction "${completionActionOption}"
    fi
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#
# Program
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Debug Mode Logging Notification
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
if [[ "${debugMode}" == "true" ]] ; then
    updateScriptLog "\n\n###\n# ${scriptVersion}\n###\n"
fi

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Display PROMT USER DIALOG
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
if [[ "${UserInformation}" == "promtUserInfo" ]]; then

    # Output Line Number in `true` Debug Mode
    if [[ "${debugMode}" == "true" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi

    # Write Welcome JSON to disk
    echo "$PromtUserJSON" > "$CommandFile"

    welcomeResults=$( eval "${dialogApp} --jsonfile ${CommandFile} --json" )

    if [[ -z "${welcomeResults}" ]]
        then
            PromtUser="2"
        else
            PromtUser="0"
    fi

    case "${PromtUser}" in

        0)  # Process exit code 0 scenario here
            echo "Exit 0"
                        
            updateScriptLog "PROMT USER DIALOG: ${loggedInUser} has received the information and has clicked on Update "

            Updates=$(get_json_value_UserInformation "$welcomeResults" "selectedValue")
            updateScriptLog "PROMT USER DIALOG: reconOptions: ${reconOptions}"

            eval "${runUpdates[*]}" & sleep 0.3
            PatchHelperProcessID=$!
            until pgrep -q -x "Dialog"; do
                # Output Line Number in `true` Debug Mode
                if [[ "${debugMode}" == "true" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi
                updateScriptLog "PROMT USER DIALOG: Waiting to display 'Patch Helper' dialog; pausing"
                sleep 0.5
            done
            updateScriptLog "PROMT USER DIALOG: 'Patch Helper' dialog displayed; ensure it's the front-most app"
            updateScriptLog "PROMT USER DIALOG: Check function ClearUpDeferral"
            ClearUpDeferral="true"
            runAsUser osascript -e 'tell application "Dialog" to activate'
            ;;

        2)  # Process exit code 2 scenario here
            echo "exit 2"
            if [[ "$CurrentDeferralValue" -gt 0 ]]
            then
                # If no LaunchDaemon is running yet, create and load it now
                if [[ "$LaunchDaemonisReady" -eq 0 ]]
                    then
                        updateScriptLog "LAUNCH-DAEMON FUNCTION: No LaunchDaemon available. Create and load it now."
                        createLaunchDaemon
                        StartLaunchDaemon
                    else
                        updateScriptLog "LAUNCH-DAEMON FUNCTION: LaunchDaemon was already active; no need to create it again."
                fi

                updateScriptLog "PROMT USER DIALOG: ${loggedInUser} clicked Quit at PROMT USER DIALOG"
                completionActionOption="Quit"
                quitScript "1"
            else
            updateScriptLog "PROMT USER DIALOG: ${loggedInUser} clicked Command Q at PROMT USER DIALOG"
            
            Updates=$(get_json_value_UserInformation "$welcomeResults" "selectedValue")
            updateScriptLog "PROMT USER DIALOG: reconOptions: ${reconOptions}"
            
            eval "${runUpdates[*]}" & sleep 0.3
            PatchHelperProcessID=$!
            until pgrep -q -x "Dialog"; do
                # Output Line Number in `true` Debug Mode
                if [[ "${debugMode}" == "true" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi
                updateScriptLog "PROMT USER DIALOG: Waiting to display 'Patch Helper' dialog; pausing"
                sleep 0.5
            done
            updateScriptLog "PROMT USER DIALOG: 'Patch Helper' dialog displayed; ensure it's the front-most app"
            runAsUser osascript -e 'tell application "Dialog" to activate'
            updateScriptLog "PROMT USER DIALOG: Check function ClearUpDeferral"
            ClearUpDeferral="true"
            fi
            ;;

        3)  # Process exit code 3 scenario here
            updateScriptLog "PROMT USER DIALOG: ${loggedInUser} clicked infobutton"
            osascript -e "set Volume 3"
            afplay /System/Library/Sounds/Glass.aiff
            ;;

        4)  # Process exit code 4 scenario here
            updateScriptLog "PROMT USER DIALOG: ${loggedInUser} allowed timer to expire"
            quitScript "1"
            ;;

        *)  # Catch all processing
            updateScriptLog "PROMT USER DIALOG: Something else happened; Exit code: ${PromtUser}"
            quitScript "1"
            ;;

    esac

else

    if [[ "${debugMode}" == "true" ]]; then updateScriptLog "PROMT USER DIALOG: # # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi
    Updates="Catch-all ('Welcome' dialog disabled)"
    # UpdateJSONConfiguration
    
    
    eval "${runUpdates[*]}" & sleep 0.3
    PatchHelperProcessID=$!
    until pgrep -q -x "Dialog"; do
        # Output Line Number in `true` Debug Mode
        if [[ "${debugMode}" == "true" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi
        updateScriptLog "PROMT USER DIALOG: Waiting to display 'Patch Helper' dialog; pausing"
        sleep 0.5
    done
    updateScriptLog "PROMT USER DIALOG: 'Patch Helper' dialog displayed; ensure it's the front-most app"
    runAsUser osascript -e 'tell application "Dialog" to activate'

fi

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Iterate through policyJSON to construct the list for swiftDialog
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Output Line Number in `true` Debug Mode
if [[ "${debugMode}" == "true" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi

dialog_step_length=$(get_json_value "${policyJSON}" "steps.length")
for (( i=0; i<dialog_step_length; i++ )); do
    listitem=$(get_json_value "${policyJSON}" "steps[$i].listitem")
    list_item_array+=("$listitem")
    icon=$(get_json_value "${policyJSON}" "steps[$i].icon")
    icon_url_array+=("$icon")
done

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Determine the "progress: increment" value based on the number of steps in policyJSON
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Output Line Number in `true` Debug Mode
if [[ "${debugMode}" == "true" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi

totalProgressSteps=$(get_json_value "${policyJSON}" "steps.length")
progressIncrementValue=$(( 100 / totalProgressSteps ))
updateScriptLog "Patch Helper DIALOG: Total Number of Steps: ${totalProgressSteps}"
updateScriptLog "Patch Helper DIALOG: Progress Increment Value: ${progressIncrementValue}"
  

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# The ${array_name[*]/%/,} expansion will combine all items within the array adding a "," character at the end
# To add a character to the start, use "/#/" instead of the "/%/"
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Output Line Number in `true` Debug Mode
if [[ "${debugMode}" == "true" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi

list_item_string=${list_item_array[*]/%/,}
PatchHelper "list: ${list_item_string%?}"
for (( i=0; i<dialog_step_length; i++ )); do
    PatchHelper "listitem: index: $i, icon: ${icon_url_array[$i]}, status: pending, statustext: Pending …"
done
PatchHelper "list: show"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Set initial progress bar
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Output Line Number in `true` Debug Mode
if [[ "${debugMode}" == "true" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi

updateScriptLog "Patch Helper DIALOG: Initial progress bar"
PatchHelper "progress: 1"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Close PROMT USER DIALOG
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Output Line Number in `true` Debug Mode
if [[ "${debugMode}" == "true" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi

dialogPatchHelper "quit:"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Update Patch Helper's infobox
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Output Line Number in `true` Debug Mode
if [[ "${debugMode}" == "true" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi

if [[ "${Updates}" == *"Catch-all"* ]]; then
    infoboxUpdates=""
else
    infoboxUpdates="${Updates}"
fi
    
    
computerName=$(scutil --get ComputerName)


infobox=""

if [[ -n ${computerName} ]]; then infobox+="**Computer Name:**  \n$computerName  \n\n" ; fi
if [[ -n ${Update_Count} ]]; then infobox+="**Updates:** :$Update_Count  \n\n" ; fi

PatchHelper "infobox: ${infobox}"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# This for loop will iterate over each distinct step in the policyJSON
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
for (( i=0; i<dialog_step_length; i++ )); do 

    # Output Line Number in `true` Debug Mode
    if [[ "${debugMode}" == "true" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi

    # Initialize SECONDS
    SECONDS="0"

    # Creating initial variables
    listitem=$(get_json_value "${policyJSON}" "steps[$i].listitem")
    icon=$(get_json_value "${policyJSON}" "steps[$i].icon")
    progresstext=$(get_json_value "${policyJSON}" "steps[$i].progresstext")
    trigger_list_length=$(get_json_value "${policyJSON}" "steps[$i].trigger_list.length")

    # If there's a value in the variable, update running swiftDialog
    if [[ -n "$listitem" ]]; then
        updateScriptLog "\n\n# * * * * * * * * * * * * * * * * * * * * * * #\n# Patch Helper DIALOG: policyJSON > listitem: ${listitem}\n# * * * * * * * * * * * * * * * * * * * * * * #\n"
        PatchHelper "listitem: index: $i, status: wait, statustext: Installing …, "
    fi
    if [[ -n "$icon" ]]; then PatchHelper "icon: ${icon}"; fi
    if [[ -n "$progresstext" ]]; then PatchHelper "progresstext: $progresstext"; fi
    if [[ -n "$trigger_list_length" ]]; then

        for (( j=0; j<trigger_list_length; j++ )); do

            # Setting variables within the trigger_list
            trigger=$(get_json_value "${policyJSON}" "steps[$i].trigger_list[$j].trigger")
            validation=$(get_json_value "${policyJSON}" "steps[$i].trigger_list[$j].validation")
            case ${validation} in
                "Local" | "Remote" )
                    updateScriptLog "Patch Helper DIALOG: Skipping Policy Execution due to '${validation}' validation"
                    ;;
                * )
                    confirmPolicyExecution "${trigger}" "${validation}"
                    ;;
            esac

        done

    fi

    validatePolicyResult "${trigger}" "${validation}"

    # Increment the progress bar
    PatchHelper "progress: increment ${progressIncrementValue}"

    # Record duration
    updateScriptLog "Patch Helper DIALOG: Elapsed Time: $(printf '%dh:%dm:%ds\n' $((SECONDS/3600)) $((SECONDS%3600/60)) $((SECONDS%60)))"

done

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Complete processing and enable the "Done" button
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Output Line Number in `true` Debug Mode
if [[ "${debugMode}" == "true" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi

finalise
