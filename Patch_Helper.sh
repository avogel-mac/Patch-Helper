#!/bin/bash
#######################################################################
# Shellscript     :   Patch Helper
# Edetiert durch  :   Andreas Vogel
#######################################################################
export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/jamf/bin/
scriptVersion="1.0.2"
debugMode="${6:-"true"}"                                 # Parameter 4: Debug Mode [ true (default) | false | verbose ]
completionActionOption="wait"                               # Completion Action [ wait | Close ]
UserInformation="promtUserInfo"
failureIcon="SF=xmark.circle.fill,weight=bold,colour1=#BB1717,colour2=#F31F1F"
macOSproductVersion="$( sw_vers -productVersion )"
macOSbuildVersion="$( sw_vers -buildVersion )"
serialNumber=$( system_profiler SPHardwareDataType | grep Serial |  awk '{print $NF}' )
timestamp="$( date '+%Y-%m-%d-%H%M%S' )"
reconOptions=""
exitCode="0"
cleanupDeferralOnExit="false"

BundleIDPlist="it.next.PatchHelper"
IconBundelPlist="it.next.icon_Service"

Managed_Preferences="/Library/Managed Preferences/${BundleIDPlist}.plist"
Managed_Icon_Service="/Library/Managed Preferences/${IconBundelPlist}.plist"

error_flag=0
if [[ ! -f "$Managed_Preferences" ]]; then
    echo "Fehler: '$Managed_Preferences' does not exist. Please configure and deploy the configuration profile via Jamf Pro."
    error_flag=1
fi

if [[ ! -f "$Managed_Icon_Service" ]]; then
    echo "Fehler: '$Managed_Icon_Service' does not exist. Please configure and deploy the configuration profile via Jamf Pro."
    error_flag=1
fi

if [[ $error_flag -eq 1 ]]; then
    exit 1
fi

missing_keys=()

get_required() {
    local keypath="$1"
    local varname="$2"
    local val
    
    val=$(/usr/libexec/PlistBuddy -c "Print $keypath" "$Managed_Preferences" 2>/dev/null)
    if [[ $? -ne 0 || -z $val ]]
        then
            missing_keys+=("$keypath")
        else
            printf -v "$varname" '%s' "$val"
    fi
}

get_required ":Daemon_and_Deferral_Settings:LaunchDaemonLabel"   LaunchDaemonLabel
get_required ":Daemon_and_Deferral_Settings:StartInterval"       StartInterval
get_required ":Daemon_and_Deferral_Settings:DaemonEventTrigger"  DaemonEventTrigger
get_required ":Daemon_and_Deferral_Settings:DeferralPlist"  DeferralPlist
get_required ":Daemon_and_Deferral_Settings:BundleIDDeferral"  BundleIDDeferral
get_required ":Dialog_Settings:BannerImage"         BannerImage
get_required ":Dialog_Settings:InfoboxIcon"         InfoboxIcon
get_required ":Dialog_Settings:button1text_wait"    button1text_wait
get_required ":Dialog_Settings:Dialog_update_width"       Dialog_update_width
get_required ":Dialog_Settings:Dialog_update_height"      Dialog_update_height
get_required ":Dialog_Settings:Dialog_update_titlefont"   Dialog_update_titlefont
get_required ":Dialog_Settings:Dialog_update_messagefont" Dialog_update_messagefont
get_required ":Dialog_Settings:Install_Button_Custom" Install_Button_Custom
get_required ":Dialog_Settings:Defer_Button_Custom"   Defer_Button_Custom
get_required ":Dialog_Settings:Dialog_quitkey"        Dialog_quitkey
get_required ":Dialog_Settings:RunUpdates_Dialog_position" RunUpdates_Dialog_position
get_required ":Dialog_Settings:Faild_Button_Custom"         Faild_Button_Custom
get_required ":Dialog_Settings:Faild_Dialog_position"       Faild_Dialog_position
get_required ":Dialog_Settings:TimePromtUser"               TimePromtUser
get_required ":Dialog_Settings:UpdateDeferral_Value"        UpdateDeferral_Value
get_required ":Dialog_Settings:Support_Telefon" Support_Telefon
get_required ":Dialog_Settings:Support_Email"   Support_Email
get_required ":ScriptLog:scriptLog"             scriptLog


if (( ${#missing_keys[@]} )); then
    echo "Error: The following required keys are missing or empty in '$Managed_Preferences':" >&2
    for key in "${missing_keys[@]}"; do
        echo "  • $key" >&2
    done
    echo "Please set these values via a configuration profile." >&2
    exit 1
fi


if [[ ! -f "${scriptLog}" ]]
    then
        touch "${scriptLog}"
    else
        if [[ $(stat -f%z "${scriptLog}") -gt 10000000 ]]; then
            zipFile="${scriptLog%.log}_$(date +'%Y-%m-%d %H:%M:%S').zip"
            zip -j "${zipFile}" "${scriptLog}"
            
            rm "${scriptLog}"
            
            touch "${scriptLog}"
            echo "$(date +'%Y-%m-%d %H:%M:%S') - log file too large, has been zipped to ${zipFile}" >> "${scriptLog}"
        fi
fi

profilesSTATUS=$(profiles status -type enrollment 2>&1)
jamfpro_url="https://$(echo "$profilesSTATUS" | grep 'MDM server' | awk -F '/' '{print $3}')"
if [[ -z "$jamfpro_url" ]]; then
    echo "Jamf Pro URL missing"
    exit 1
fi

jamf_api_client="$4"
if [[ -z "$jamf_api_client" ]]; then
    if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]]
    then
        echo "Function-Check Jamf API debugMode: Jamf Pro Client Secret is missing"
        echo "Function-Check Jamf API debugMode: Skript running in Debug Mode Testing of API Calls not possible"
    else
        echo "Function-Check Jamf API: Jamf Pro Client Secret is missing"
        echo "# * * * * * * * * * * * * * * * * * * * * * * * END WITH ERROR * * * * * * * * * * * * * * * * * * * * * * * #"
        exit 1
    fi
fi

jamf_api_secret="$5"
if [[ -z "$jamf_api_secret" ]]; then
    if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]]
    then
        echo "Function-Check Jamf API debugMode: Jamf Pro Client Secret is missing"
        echo "Function-Check Jamf API debugMode: Skript running in Debug Mode Testing of API Calls not possible"
        
    else
        echo "Function-Check Jamf API: Jamf Pro Client Secret is missing"
        echo "# * * * * * * * * * * * * * * * * * * * * * * * END WITH ERROR * * * * * * * * * * * * * * * * * * * * * * * #"
        exit 1
    fi
fi

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# WARM-UPs
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
function updateScriptLog() {
    if [[ "${debugMode}" == "verbose" ]]
    then
        echo -e "$( date +%Y-%m-%d\ %H:%M:%S ) - Line No. ${BASH_LINENO[0]} - ${1}" | tee -a "${scriptLog}"
    else
        echo -e "$( date +%Y-%m-%d\ %H:%M:%S ) - ${1}" | tee -a "${scriptLog}"
    fi
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
    if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "WARM-UP: # # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi

    # Get the URL of the latest PKG From the Dialog GitHub repo
    dialogURL=$(curl -L --silent --fail "https://api.github.com/repos/swiftDialog/swiftDialog/releases/latest" | awk -F '"' "/browser_download_url/ && /pkg\"/ { print \$4; exit }")
        
    expectedDialogTeamID="PWA5E9TQ59"

    # Check for Dialog and install if not found
    if [ ! -e "/Library/Application Support/Dialog/Dialog.app" ]
        then
            updateScriptLog "PRE-FLIGHT CHECK: Dialog not found. Installing..."
    
            workDirectory=$( /usr/bin/basename "$0" )
            tempDirectory=$( /usr/bin/mktemp -d "/private/tmp/$workDirectory.XXXXXX" )
    
            /usr/bin/curl --location --silent "$dialogURL" -o "$tempDirectory/Dialog.pkg"
    
            teamID=$(/usr/sbin/spctl -a -vv -t install "$tempDirectory/Dialog.pkg" 2>&1 | awk '/origin=/ {print $NF }' | tr -d '()')
    
            if [[ "$expectedDialogTeamID" == "$teamID" ]]
                then
                    /usr/sbin/installer -pkg "$tempDirectory/Dialog.pkg" -target /
                    sleep 2
                    dialogVersion=$( /usr/local/bin/dialog --version )
                    updateScriptLog "PRE-FLIGHT CHECK: swiftDialog version ${dialogVersion} installed; proceeding..."
        
                else
                    osascript -e 'display dialog "Please advise your Support Representative of the following error:\r\r• Dialog Team ID verification failed\r\r" with title "Patch Helper: Error" buttons {"Close"} with icon caution'
                    completionActionOption="Quit"
                    exitCode="1"
                    /bin/rm -Rf "$tempDirectory"
                    exit 1
    
            fi
            /bin/rm -Rf "$tempDirectory"
    
        else
            updateScriptLog "PRE-FLIGHT CHECK: swiftDialog version $(/usr/local/bin/dialog --version) found; proceeding..."

    fi
}

if [[ ! -e "/Library/Application Support/Dialog/Dialog.app" ]]
    then
        dialogCheck
    else
        updateScriptLog "PRE-FLIGHT CHECK: swiftDialog version $(/usr/local/bin/dialog --version) found; proceeding..."
fi

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Deferral Handling
setDeferralCount() {
    local BundleID="$1"
    local UpdateDeferral_Value="$2"
    local DeferralPlist="$3"
    
    local DeferralCount
    DeferralCount="$(/usr/libexec/PlistBuddy -c "print :${BundleID}:count" "$DeferralPlist" 2>/dev/null)"
    
    if [[ -n "$DeferralCount" ]] && [[ ! "$DeferralCount" =~ "File Doesn't Exist" ]]
        then
            /usr/libexec/PlistBuddy -c "set :${BundleID}:count $UpdateDeferral_Value" "$DeferralPlist" 2>/dev/null
        else
            /usr/libexec/PlistBuddy -c "add :${BundleID}:count integer $UpdateDeferral_Value" "$DeferralPlist" 2>/dev/null
    fi
}


CurrentDeferralValue="$(/usr/libexec/PlistBuddy -c "print :${BundleIDDeferral}:count" "$DeferralPlist" 2>/dev/null)"
if [[ -z "$CurrentDeferralValue" ]] || [[ "$CurrentDeferralValue" =~ "File Doesn't Exist" ]]; then
    setDeferralCount "$BundleIDDeferral" "$UpdateDeferral_Value" "$DeferralPlist"
    CurrentDeferralValue="$(/usr/libexec/PlistBuddy -c "print :${BundleIDDeferral}:count" "$DeferralPlist" 2>/dev/null)"
fi

echo "Current deferral count for ${BundleIDDeferral}: $CurrentDeferralValue"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# PRE-FLIGHT CHECK: Complete
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

updateScriptLog "PRE-FLIGHT CHECK: Complete"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# LaunchDaemon lifecycle
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

LaunchDaemonPlist="/Library/LaunchDaemons/$LaunchDaemonLabel.plist"
LaunchDaemonService="system/$LaunchDaemonLabel"
LaunchDaemonPlistExists="false"
LaunchDaemonLoaded="false"
LaunchDaemonisReady=0

function refreshLaunchDaemonState() {
    LaunchDaemonPlistExists="false"
    LaunchDaemonLoaded="false"
    LaunchDaemonisReady=0

    if [[ -f "$LaunchDaemonPlist" ]]; then
        LaunchDaemonPlistExists="true"
    fi

    if /bin/launchctl print "$LaunchDaemonService" >/dev/null 2>&1; then
        LaunchDaemonLoaded="true"
    fi

    if [[ "$LaunchDaemonPlistExists" == "true" && "$LaunchDaemonLoaded" == "true" ]]; then
        LaunchDaemonisReady=1
    fi
}

refreshLaunchDaemonState
updateScriptLog "LAUNCH-DAEMON FUNCTION: Initial state - plist=${LaunchDaemonPlistExists}, loaded=${LaunchDaemonLoaded}, ready=${LaunchDaemonisReady}."

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Helper functions: cleanup
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function ClearUpPlist() {
    if [[ -e "$DeferralPlist" ]]; then
        updateScriptLog "QUIT SCRIPT: Removing deferral plist '$DeferralPlist'."
        if /bin/rm -f "$DeferralPlist"; then
            updateScriptLog "QUIT SCRIPT: Deferral plist removed successfully."
        else
            updateScriptLog "QUIT SCRIPT: ERROR: Could not remove deferral plist '$DeferralPlist'."
            return 1
        fi
    else
        updateScriptLog "QUIT SCRIPT: Deferral plist does not exist; nothing to remove."
    fi

    return 0
}

function ClearUpLaunchDaemon() {
    local bootoutOutput=""
    local bootoutResult=0

    refreshLaunchDaemonState
    updateScriptLog "QUIT SCRIPT: LaunchDaemon cleanup - plist=${LaunchDaemonPlistExists}, loaded=${LaunchDaemonLoaded}."

    # Remove persistence first. This is intentional: this script may itself have
    # been started by the LaunchDaemon. bootout is therefore performed last.
    if [[ "$LaunchDaemonPlistExists" == "true" ]]; then
        updateScriptLog "QUIT SCRIPT: Removing LaunchDaemon plist '$LaunchDaemonPlist'."

        if ! /bin/rm -f "$LaunchDaemonPlist"; then
            updateScriptLog "QUIT SCRIPT: ERROR: Could not remove LaunchDaemon plist '$LaunchDaemonPlist'."
            return 1
        fi

        if [[ -e "$LaunchDaemonPlist" ]]; then
            updateScriptLog "QUIT SCRIPT: ERROR: LaunchDaemon plist still exists after rm."
            return 1
        fi

        LaunchDaemonPlistExists="false"
        LaunchDaemonisReady=0
        updateScriptLog "QUIT SCRIPT: LaunchDaemon plist removed successfully."
    else
        updateScriptLog "QUIT SCRIPT: LaunchDaemon plist does not exist; nothing to remove."
    fi

    if [[ "$LaunchDaemonLoaded" == "true" ]]; then
        updateScriptLog "QUIT SCRIPT: Booting out '$LaunchDaemonService' as final LaunchDaemon cleanup action."

        bootoutOutput=$(/bin/launchctl bootout "$LaunchDaemonService" 2>&1)
        bootoutResult=$?

        if [[ $bootoutResult -ne 0 ]]; then
            updateScriptLog "QUIT SCRIPT: ERROR: bootout failed (${bootoutResult}): ${bootoutOutput}"
            return 1
        fi

        # If this shell survives bootout, update the local state. When this script
        # was launched by the daemon, launchd may terminate the process tree here.
        LaunchDaemonLoaded="false"
        LaunchDaemonisReady=0
        updateScriptLog "QUIT SCRIPT: LaunchDaemon bootout command completed successfully."
    else
        updateScriptLog "QUIT SCRIPT: LaunchDaemon is not loaded; bootout not required."
    fi

    return 0
}

function CleanupDeferralState() {
    local cleanupResult=0

    updateScriptLog "QUIT SCRIPT: Cleaning deferral state and LaunchDaemon."

    ClearUpPlist || cleanupResult=1
    ClearUpLaunchDaemon || cleanupResult=1

    return "$cleanupResult"
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Create and start LaunchDaemon
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

function createLaunchDaemon() {
    local tempLaunchDaemonPlist="${LaunchDaemonPlist}.tmp.$$"

    updateScriptLog "LAUNCH-DAEMON FUNCTION: Creating LaunchDaemon plist '$LaunchDaemonPlist'."

    /bin/cat <<EOC > "$tempLaunchDaemonPlist"
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
    <string>${DaemonEventTrigger}</string>
</array>
<key>RunAtLoad</key>
<false/>
<key>StartInterval</key>
<integer>${StartInterval}</integer>
<key>UserName</key>
<string>root</string>
</dict>
</plist>
EOC

    if [[ $? -ne 0 ]]; then
        updateScriptLog "LAUNCH-DAEMON FUNCTION: ERROR: Could not write temporary LaunchDaemon plist."
        /bin/rm -f "$tempLaunchDaemonPlist"
        return 1
    fi

    if ! /usr/bin/plutil -lint "$tempLaunchDaemonPlist" >/dev/null 2>&1; then
        updateScriptLog "LAUNCH-DAEMON FUNCTION: ERROR: Generated LaunchDaemon plist is invalid."
        /bin/rm -f "$tempLaunchDaemonPlist"
        return 1
    fi

    if ! /usr/sbin/chown root:wheel "$tempLaunchDaemonPlist"; then
        updateScriptLog "LAUNCH-DAEMON FUNCTION: ERROR: chown failed for temporary LaunchDaemon plist."
        /bin/rm -f "$tempLaunchDaemonPlist"
        return 1
    fi

    if ! /bin/chmod 644 "$tempLaunchDaemonPlist"; then
        updateScriptLog "LAUNCH-DAEMON FUNCTION: ERROR: chmod failed for temporary LaunchDaemon plist."
        /bin/rm -f "$tempLaunchDaemonPlist"
        return 1
    fi

    if ! /bin/mv -f "$tempLaunchDaemonPlist" "$LaunchDaemonPlist"; then
        updateScriptLog "LAUNCH-DAEMON FUNCTION: ERROR: Could not move LaunchDaemon plist into place."
        /bin/rm -f "$tempLaunchDaemonPlist"
        return 1
    fi

    refreshLaunchDaemonState
    updateScriptLog "LAUNCH-DAEMON FUNCTION: LaunchDaemon plist created successfully."
    return 0
}

function StartLaunchDaemon() {
    local bootstrapOutput=""
    local bootstrapResult=0

    refreshLaunchDaemonState

    if [[ "$LaunchDaemonLoaded" == "true" ]]; then
        updateScriptLog "LAUNCH-DAEMON FUNCTION: '$LaunchDaemonLabel' is already loaded."
        [[ "$LaunchDaemonPlistExists" == "true" ]] && LaunchDaemonisReady=1
        return 0
    fi

    if [[ "$LaunchDaemonPlistExists" != "true" ]]; then
        updateScriptLog "LAUNCH-DAEMON FUNCTION: ERROR: LaunchDaemon plist is missing; bootstrap aborted."
        return 1
    fi

    if ! /usr/bin/plutil -lint "$LaunchDaemonPlist" >/dev/null 2>&1; then
        updateScriptLog "LAUNCH-DAEMON FUNCTION: ERROR: LaunchDaemon plist is invalid; bootstrap aborted."
        return 1
    fi

    updateScriptLog "LAUNCH-DAEMON FUNCTION: Bootstrapping '$LaunchDaemonService'."
    bootstrapOutput=$(/bin/launchctl bootstrap system "$LaunchDaemonPlist" 2>&1)
    bootstrapResult=$?

    # Always verify the actual state. A concurrent load can make bootstrap return
    # non-zero even though the service is now available.
    refreshLaunchDaemonState

    if [[ "$LaunchDaemonLoaded" == "true" ]]; then
        LaunchDaemonisReady=1
        updateScriptLog "LAUNCH-DAEMON FUNCTION: LaunchDaemon is loaded and ready."
        return 0
    fi

    updateScriptLog "LAUNCH-DAEMON FUNCTION: ERROR: bootstrap failed (${bootstrapResult}): ${bootstrapOutput}"
    updateScriptLog "LAUNCH-DAEMON FUNCTION: Removing unusable LaunchDaemon plist."
    /bin/rm -f "$LaunchDaemonPlist"
    refreshLaunchDaemonState
    return 1
}

function EnsureLaunchDaemon() {
    refreshLaunchDaemonState
    updateScriptLog "LAUNCH-DAEMON FUNCTION: Ensure state - plist=${LaunchDaemonPlistExists}, loaded=${LaunchDaemonLoaded}."

    if [[ "$LaunchDaemonPlistExists" == "true" ]]; then
        if ! /usr/bin/plutil -lint "$LaunchDaemonPlist" >/dev/null 2>&1; then
            updateScriptLog "LAUNCH-DAEMON FUNCTION: Existing plist is invalid; replacing it."
            /bin/rm -f "$LaunchDaemonPlist"
            LaunchDaemonPlistExists="false"
            LaunchDaemonisReady=0
        fi
    fi

    if [[ "$LaunchDaemonPlistExists" != "true" ]]; then
        if ! createLaunchDaemon; then
            updateScriptLog "LAUNCH-DAEMON FUNCTION: ERROR: Could not create LaunchDaemon."
            return 1
        fi
    fi

    refreshLaunchDaemonState

    if [[ "$LaunchDaemonLoaded" != "true" ]]; then
        if ! StartLaunchDaemon; then
            updateScriptLog "LAUNCH-DAEMON FUNCTION: ERROR: Could not load LaunchDaemon."
            return 1
        fi
    fi

    refreshLaunchDaemonState

    if [[ "$LaunchDaemonisReady" -eq 1 ]]; then
        updateScriptLog "LAUNCH-DAEMON FUNCTION: LaunchDaemon is ready."
        return 0
    fi

    updateScriptLog "LAUNCH-DAEMON FUNCTION: ERROR: LaunchDaemon is not ready after ensure operation."
    return 1
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Auth / Policies
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
function get_api_token() {
    
    validToken="false"
    
    if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]]
    then
        updateScriptLog "Function-GET API Token debugMode: debugMode is activated"
        updateScriptLog "Function-GET API Token debugMode: try to call the API if credentials are available"
        
        if [[ -n "$jamf_api_client" && -n "$jamf_api_secret" ]]
        then
            curl_response=$(curl --silent --location --request POST "${jamfpro_url}/api/oauth/token" --header "Content-Type: application/x-www-form-urlencoded" --data-urlencode "client_id=${jamf_api_client}" --data-urlencode "grant_type=client_credentials" --data-urlencode "client_secret=${jamf_api_secret}")
            
            if [[ $(echo "${curl_response}" | grep -c 'token') -gt 0 ]]
                then
                    if [[ $(sw_vers -productVersion | cut -d'.' -f1) -lt 12 ]]
                        then
                            api_token=$(echo "${curl_response}" | plutil -extract access_token raw -)
                        else 
                            api_token=$(echo "${curl_response}" | awk -F '"' '{print $4;}' | xargs)
                    fi
                    updateScriptLog "Function-GET API Token: Token was successfully generated"
                    validToken="true"
                else
                    updateScriptLog "Function-GET API Token: Token could not be generated"
                    updateScriptLog "Function-GET API Token: Verify the --auth-jamf-client=ClientID and --auth-jamf-secret=ClientSecret are values."
                    
                    updateScriptLog "# * * * * * * * * * * * * * * * * * * * * * * * END WITH ERROR * * * * * * * * * * * * * * * * * * * * * * * #"
                    exit 1
            fi
        else
            updateScriptLog "Function-GET API Token debugMode: no credentials available."
            updateScriptLog "Function-GET API Token debugMode: Continue with the test to display the dialogues."
        fi
        
    else
        
        curl_response=$(curl --silent --location --request POST "${jamfpro_url}/api/oauth/token" --header "Content-Type: application/x-www-form-urlencoded" --data-urlencode "client_id=${jamf_api_client}" --data-urlencode "grant_type=client_credentials" --data-urlencode "client_secret=${jamf_api_secret}")
        
        if [[ $(echo "${curl_response}" | grep -c 'token') -gt 0 ]]
            then
                if [[ $(sw_vers -productVersion | cut -d'.' -f1) -lt 12 ]]
                    then
                        api_token=$(echo "${curl_response}" | plutil -extract access_token raw -)
                    else 
                        api_token=$(echo "${curl_response}" | awk -F '"' '{print $4;}' | xargs)
                fi
                updateScriptLog "Function-GET API Token: Token was successfully generated"
                validToken="true"
            else
                updateScriptLog "Function-GET API Token: Token could not be generated"
                updateScriptLog "Function-GET API Token: Verify the --auth-jamf-client=ClientID and --auth-jamf-secret=ClientSecret are values."
                updateScriptLog "# * * * * * * * * * * * * * * * * * * * * * * * END WITH ERROR * * * * * * * * * * * * * * * * * * * * * * * #"
                exit 1
        fi
    fi
}
    
get_api_token
    

if [[ "$validToken" == "true" ]]
then
    response=$(/usr/bin/curl -X GET "$jamfpro_url/JSSResource/computermanagement/udid/$(system_profiler SPHardwareDataType | grep UUID | awk '" " { print $NF }')/subset/policies" -H "accept: application/xml" -H "Authorization: Bearer ${api_token}")
    
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
    
    initial_Update_Count=$(/usr/libexec/PlistBuddy -c "Print :ApplicationCount" "$plistOutput" 2>/dev/null)
    updateScriptLog "CHECK-FOR-UPDATES FUNCTION: The total number of updates is: $initial_Update_Count"
    
else
    policyJSON='
                {
                    "steps": [
                        {
                            "listitem": "TEST Slack",
                            "icon": "https://ics.services.jamfcloud.com/icon/hash_a1ecbe1a4418113177cc061def4996d20a01a1e9b9adf9517899fcca31f3c026",
                            "progresstext": "Updating TEST Policy Slack",
                            "trigger_list": [
                                {
                                    "trigger": "",
                                    "validation": "None"
                                }
                            ]
                        },
                        {
                            "listitem": "TEST The Unarchiver",
                            "icon": "https://ics.services.jamfcloud.com/icon/hash_5ef15847e6f8b29cedf4e97a468d0cb1b67ec1dcef668d4493bf6537467a02c2",
                            "progresstext": "Updating TEST The Unarchiver",
                            "trigger_list": [
                                {
                                    "trigger": "",
                                    "validation": "None"
                                }
                            ]
                        },
                        {
                            "listitem": "TEST Figma",
                            "icon": "https://ics.services.jamfcloud.com/icon/hash_ad7d074540cf041f9d9857ecf6c0223e38fb8e582168484b97ae95bd7b5a53de",
                            "progresstext": "Updating TEST Figma",
                            "trigger_list": [
                                {
                                    "trigger": "",
                                    "validation": "None"
                                }
                            ]
                        },
                        {
                            "listitem": "Update Inventory",
                            "icon": "https://ics.services.jamfcloud.com/icon/hash_ff2147a6c09f5ef73d1c4406d00346811a9c64c0b6b7f36eb52fcb44943d26f9",
                            "progresstext": "Updating Inventory",
                            "trigger_list": [
                                {
                                    "trigger": "recon",
                                    "validation": "None"
                                }
                            ]
                        }
                    ]
                }
                '
    initial_Update_Count="3"
    Update_Count="3"
    joinedPolicyNames="Slack, The Unarchiver, Figma"
    
fi
    
function invalidateToken() {
    if [[ "$validToken" != "true" || -z "${api_token:-}" ]]; then
        updateScriptLog "QUIT SCRIPT: No valid API token available; invalidation skipped."
        return 0
    fi

    responseCode=$(curl -w "%{http_code}" -H "Authorization: Bearer ${api_token}" "$jamfpro_url/api/v1/auth/invalidate-token" -X POST -s -o /dev/null)
    if [[ ${responseCode} == 204 ]]; then
        updateScriptLog "QUIT SCRIPT: Token successfully invalidated"
        validToken="false"
        api_token=""
    elif [[ ${responseCode} == 401 ]]; then
        updateScriptLog "QUIT SCRIPT: Token already invalid"
        validToken="false"
        api_token=""
    else
        updateScriptLog "QUIT SCRIPT: An unknown error occurred invalidating the token (HTTP ${responseCode})"
        return 1
    fi

    return 0
}


if [[ "$initial_Update_Count" -eq 0 ]]; then
    updateScriptLog "CHECK-FOR-UPDATES FUNCTION: no patches found, exiting"
    invalidateToken
    updateScriptLog "CHECK-FOR-UPDATES FUNCTION: Removing deferral state because no updates remain."
    CleanupDeferralState
    exit 0
fi

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# infobox-related variables
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
dialogVersion=$( /usr/local/bin/dialog --version )
case ${debugMode} in
    "true"   ) scriptVersion="DEBUG MODE | Dialog: v${dialogVersion} • Patch Helper: v${scriptVersion}" ;;
    "false"   ) scriptVersion="Patch Helper | v${scriptVersion}" ;;
    "verbose" ) scriptVersion="Verbose MODE | Dialog: v${dialogVersion} • Patch Helper: v${scriptVersion}" ;;
esac

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Set Dialog path, Command Files, JAMF binary, log files and currently logged-in user
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
dialogBinary="/usr/local/bin/dialog"
CommandFile=$( mktemp /var/tmp/dialogWelcome.XXX )
PatchHelperCommandFile=$( mktemp /var/tmp/dialogPatchHelper.XXX )
failureCommandFile=$( mktemp /var/tmp/dialogFailure.XXX )
chmod 755 "$CommandFile" "$PatchHelperCommandFile" "$failureCommandFile"

jamfBinary="/usr/local/bin/jamf"

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

# Loads icon, validation and BundelID from the central plist
function LoadPolicyAttributes() {
    local policyName="$1"
    local key found=false
    
    # 1) exakter Key
    key="$policyName"
    if /usr/libexec/PlistBuddy -c "Print :'${key}':BundelID" "$Managed_Icon_Service" &>/dev/null
        then
            found=true
        else
            # 2) Underscore key
            key=$(echo "$policyName" | sed 's/[ \/]/_/g')
            if /usr/libexec/PlistBuddy -c "Print :'${key}':BundelID" "$Managed_Icon_Service" &>/dev/null
                then
                    found=true
                else
                    # 3) Fuzzy match across all keys
                    while IFS= read -r cand; do
                        cKey=$(echo "$cand" | tr -d ' _' | tr '[:upper:]' '[:lower:]')
                        cName=$(echo "$policyName" | tr -d ' _' | tr '[:upper:]' '[:lower:]')
                        if [[ "$cKey" == *"$cName"* ]] || [[ "$cName" == *"$cKey"* ]]; then
                            key="$cand"
                            found=true
                            break
                        fi
                    done < <(
                                    /usr/libexec/PlistBuddy -c "Print" "$Managed_Icon_Service" \
                                    | awk -F= '/^[[:space:]]*[A-Za-z0-9 _]+ = Dict/ {
                                                        k=$1; gsub(/^[[:space:]]+|[[:space:]]+$/,"",k);
                                                        print k
                                                }'
                            )
            fi
    fi
    
    if [[ "$found" == true ]]
        then
            BundelID=$(/usr/libexec/PlistBuddy -c "Print :'${key}':BundelID"    "$Managed_Icon_Service" 2>/dev/null) || BundelID=""
            icon=$(/usr/libexec/PlistBuddy -c "Print :'${key}':icon"        "$Managed_Icon_Service" 2>/dev/null) || icon=""
            validation=$(/usr/libexec/PlistBuddy -c "Print :'${key}':validation" "$Managed_Icon_Service" 2>/dev/null) || validation=""
        else
            BundelID=""; icon=""; validation=""
    fi
    
    # Fallback-Defaults
    [[ -z "$icon"       ]] && icon="https://ics.services.jamfcloud.com/icon/hash_ff2147a6c09f5ef73d1c4406d00346811a9c64c0b6b7f36eb52fcb44943d26f9"
    [[ -z "$validation" ]] && validation="None"
}

function UpdateJSONConfiguration() {
    Update_Count_in_background=0
    updatedApps=()
    PolicyNameUserPrompt=()
    
    Update_Count=$(/usr/libexec/PlistBuddy -c "Print :ApplicationCount" "$plistOutput" 2>/dev/null)
    IDs=($(get_PolicyIDs))
    
    policyJSON='{"steps": ['
    addedObjects=0
    
    for PolicyID in "${IDs[@]}"; do
        PolicyName="$(GetPolicyName "$PolicyID")"
        LoadPolicyAttributes "$PolicyName"
        
        if [[ -z "$BundelID" || "$BundelID" == "None" ]]; then
            (( addedObjects > 0 )) && policyJSON+=','
            policyJSON+='{
                            "listitem":"'"${PolicyName}"'",
                            "icon":"'"${icon}"'",
                            "progresstext":"Updating '"${PolicyName}"'",
                            "trigger_list":[{"trigger":"'"${PolicyID}"'","validation":"'"${validation}"'"}]
                    }'
            (( addedObjects++ ))
            PolicyNameUserPrompt+=( "$PolicyName" )
        else
            result=$(/bin/launchctl asuser "$loggedInUserID" sudo -iu "$loggedInUser" \
                                        /bin/launchctl list 2>/dev/null | grep -F "$BundelID")
            if [[ -z "$result" ]]; then
                updateScriptLog "BACKGROUND-UPDATER: $PolicyName (trigger $PolicyID) is now executed."
                /usr/local/bin/jamf policy -id "$PolicyID" -forceNoRecon
                backgroundPolicyExitCode=$?

                if [[ $backgroundPolicyExitCode -eq 0 ]]; then
                    updateScriptLog "BACKGROUND-UPDATER: $PolicyName completed successfully."
                    (( Update_Count-- ))
                    (( Update_Count_in_background++ ))
                    updatedApps+=( "$PolicyName" )

                    if [[ $Update_Count -eq 0 ]]; then
                        updateScriptLog "BACKGROUND-UPDATER: All apps updated in the background. Inventory is sent."
                        /usr/local/bin/jamf recon
                        reconExitCode=$?

                        if [[ $reconExitCode -eq 0 ]]; then
                            invalidateToken
                            CleanupDeferralState
                            exit 0
                        else
                            updateScriptLog "BACKGROUND-UPDATER: ERROR: Inventory update failed with exit code ${reconExitCode}; preserving deferral state."
                            invalidateToken
                            exit 1
                        fi
                    fi
                else
                    updateScriptLog "BACKGROUND-UPDATER: ERROR: $PolicyName failed with exit code ${backgroundPolicyExitCode}; moving it to the user update workflow."
                    (( addedObjects > 0 )) && policyJSON+=','
                    policyJSON+='{
                                        "listitem":"'"${PolicyName}"'",
                                        "icon":"'"${icon}"'",
                                        "progresstext":"Updating '"${PolicyName}"'",
                                        "trigger_list":[{"trigger":"'"${PolicyID}"'","validation":"'"${validation}"'"}]
                                }'
                    (( addedObjects++ ))
                    PolicyNameUserPrompt+=( "$PolicyName" )
                fi
            else
                (( addedObjects > 0 )) && policyJSON+=','
                policyJSON+='{
                                    "listitem":"'"${PolicyName}"'",
                                    "icon":"'"${icon}"'",
                                    "progresstext":"Updating '"${PolicyName}"'",
                                    "trigger_list":[{"trigger":"'"${PolicyID}"'","validation":"'"${validation}"'"}]
                            }'
                (( addedObjects++ ))
                PolicyNameUserPrompt+=( "$PolicyName" )
            fi
        fi
    done
    
    (( addedObjects > 0 )) && policyJSON+=','
    policyJSON+='{
            "listitem":"Update Inventory",
            "icon":"https://ics.services.jamfcloud.com/icon/hash_ff2147a6c09f5ef73d1c4406d00346811a9c64c0b6b7f36eb52fcb44943d26f9",
            "progresstext":"Updating Inventory",
            "trigger_list":[{"trigger":"recon","validation":"None"}]
    }]
    }'
    
    updateScriptLog "BACKGROUND-CHECK: Remaining updates: $Update_Count"
    if (( Update_Count_in_background > 0 )); then
        updateScriptLog "BACKGROUND-CHECK: Updated in the background: $Update_Count_in_background → ${updatedApps[*]}"
    else
        updateScriptLog "BACKGROUND-CHECK: No background updates possible"
    fi
    if ((${#PolicyNameUserPrompt[@]})); then
        joinedPolicyNames=$(IFS=', '; echo "${PolicyNameUserPrompt[*]}")
        updateScriptLog "BACKGROUND-CHECK: Not updated in the background: $joinedPolicyNames"
    fi
}

if [[ "$validToken" == "true" ]]; then
UpdateJSONConfiguration
fi
    
echo $policyJSON

if [[ "$Update_Count" -eq 1 ]]
    then
        UserInfoTitle_SINGLE=$(/usr/libexec/PlistBuddy -c "Print :Messages:UserInfoTitle_Single" "$Managed_Preferences" 2>/dev/null)
        UserInfoTitle_SINGLE="$(printf '%s\n' "$UserInfoTitle_SINGLE" | /usr/bin/sed "s/%REAL_FIRSTNAME%/${loggedInUserFirstname}/" | /usr/bin/sed "s/%UPDATE_COUNT%/${Update_Count}/")"
        
        final_sucess_progresstext_SINGLE=$(/usr/libexec/PlistBuddy -c "Print :Messages:final_sucess_progresstext_Single" "$Managed_Preferences" 2>/dev/null)
        final_sucess_progresstext_SINGLE="$(printf '%s\n' "$final_sucess_progresstext_SINGLE" | /usr/bin/sed "s/%REAL_FIRSTNAME%/${loggedInUserFirstname}/" | /usr/bin/sed "s/%UPDATE_COUNT%/${Update_Count}/")"
        
        UserInfoTitle="$UserInfoTitle_SINGLE"
        final_sucess_progresstext="$final_sucess_progresstext_SINGLE"
    else
        UserInfoTitle_MULTIPLE=$(/usr/libexec/PlistBuddy -c "Print :Messages:UserInfoTitle_Multi" "$Managed_Preferences" 2>/dev/null)
        UserInfoTitle_MULTIPLE="$(printf '%s\n' "$UserInfoTitle_MULTIPLE" | /usr/bin/sed "s/%REAL_FIRSTNAME%/${loggedInUserFirstname}/" | /usr/bin/sed "s/%UPDATE_COUNT%/${Update_Count}/")"
        
        final_sucess_progresstext_MULTIPLE=$(/usr/libexec/PlistBuddy -c "Print :Messages:final_sucess_progresstext_Multi" "$Managed_Preferences" 2>/dev/null)
        final_sucess_progresstext_MULTIPLE="$(printf '%s\n' "$final_sucess_progresstext_MULTIPLE" | /usr/bin/sed "s/%REAL_FIRSTNAME%/${loggedInUserFirstname}/" | /usr/bin/sed "s/%UPDATE_COUNT%/${Update_Count}/")"
        
        UserInfoTitle="$UserInfoTitle_MULTIPLE"
        final_sucess_progresstext="$final_sucess_progresstext_MULTIPLE"
fi
    
UserInfoMessage=$(/usr/libexec/PlistBuddy -c "Print :Messages:UserInfoMessage" "$Managed_Preferences" 2>/dev/null)
UserInfoMessage="$(printf '%s\n' "$UserInfoMessage" | /usr/bin/sed "s/%joinedPolicyNames%/${joinedPolicyNames[*]}/" | /usr/bin/sed "s/%CURRENT_DEFERRAL_VALUE%/${CurrentDeferralValue}/")"



UserEnforceMessage=$(/usr/libexec/PlistBuddy -c "Print :Messages:UserEnforceMessage" "$Managed_Preferences" 2>/dev/null)
UserEnforceMessage="$(printf '%s\n' "$UserEnforceMessage" | /usr/bin/sed "s/%joinedPolicyNames%/${joinedPolicyNames[*]}/" | /usr/bin/sed "s/%CURRENT_DEFERRAL_VALUE%/${CurrentDeferralValue}/" | /usr/bin/sed "s/%REAL_FIRSTNAME%/${loggedInUserFirstname}/" | /usr/bin/sed "s/%NAMES_DISPLAY%/${Names_display[*]}/")"


title=$(/usr/libexec/PlistBuddy -c "Print :Messages:title" "$Managed_Preferences" 2>/dev/null)
message=$(/usr/libexec/PlistBuddy -c "Print :Messages:message" "$Managed_Preferences" 2>/dev/null)
failureTitle=$(/usr/libexec/PlistBuddy -c "Print :Messages:failureTitle" "$Managed_Preferences" 2>/dev/null)
final_sucess_titel=$(/usr/libexec/PlistBuddy -c "Print :Messages:final_sucess_titel" "$Managed_Preferences" 2>/dev/null)
progresstext=$(/usr/libexec/PlistBuddy -c "Print :Messages:progresstext" "$Managed_Preferences" 2>/dev/null)

helpmessage=$(/usr/libexec/PlistBuddy -c "Print :Messages:helpmessage" "$Managed_Preferences" 2>/dev/null)
helpmessage="$(printf '%s\n' "$helpmessage" | /usr/bin/sed "s/%SUPPORT_TELEFON%/${Support_Telefon}/" | /usr/bin/sed "s/%SUPPORT_EMAIL%/${Support_Email}/" | /usr/bin/sed "s/%MACOSPRDICTVERSION%/${macOSproductVersion} ($macOSbuildVersion)/" | /usr/bin/sed "s/%SERIALNUMBER%/${serialNumber}/" | /usr/bin/sed "s/%DIALOG_VERSION%/${dialogVersion}/" | /usr/bin/sed "s/%TIME_STAMP%/${timestamp}/")"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#
# PROMPT DIALOG
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# "Promt User for Updates" JSON
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
case ${debugMode} in
    "false"     ) dialogBinary="${dialogBinary}" ;;
    "true"      ) dialogBinary="${dialogBinary} --verbose" ;;
    "verbose"   ) dialogBinary="${dialogBinary} --verbose --resizable --debug red" ;;
esac

# Build the item list for the first prompt window from policyJSON.
# Each --listitem contains the policy/application name and its icon.
function get_prompt_json_value() {
    JSON="$1" /usr/bin/osascript -l JavaScript \
        -e 'const env = $.NSProcessInfo.processInfo.environment.objectForKey("JSON").js' \
        -e "JSON.parse(env).$2"
}

PromptListArguments=""
PromptListLength="$(get_prompt_json_value "${policyJSON}" "steps.length" 2>/dev/null)"

if [[ "${PromptListLength}" =~ ^[0-9]+$ ]] && (( PromptListLength > 0 )); then
    for (( PromptListIndex=0; PromptListIndex<PromptListLength; PromptListIndex++ )); do
        PromptListName="$(get_prompt_json_value "${policyJSON}" "steps[${PromptListIndex}].listitem" 2>/dev/null)"
        PromptListIcon="$(get_prompt_json_value "${policyJSON}" "steps[${PromptListIndex}].icon" 2>/dev/null)"

        [[ "${PromptListName}" == "undefined" || "${PromptListName}" == "null" ]] && PromptListName=""
        [[ "${PromptListIcon}" == "undefined" || "${PromptListIcon}" == "null" ]] && PromptListIcon=""

        if [[ -n "${PromptListName}" ]]; then
            PromptListValue="${PromptListName}"
            [[ -n "${PromptListIcon}" ]] && PromptListValue+=",icon=${PromptListIcon}"

            # PromtUser is executed with eval later. %q ensures that spaces and
            # shell metacharacters in policy names or icon URLs remain one argument.
            printf -v PromptListQuoted '%q' "${PromptListValue}"
            PromptListArguments+=" --listitem ${PromptListQuoted}"
        fi
    done
else
    updateScriptLog "PROMT USER DIALOG: policyJSON could not be parsed; prompt list will be omitted."
fi

if [[ "$CurrentDeferralValue" -gt 0 ]]
    then
            # The deferral counter is reduced only after the user actually defers
            # or the timer expires. Merely displaying the prompt must not consume it.
            PromtUser="$dialogBinary \
            --bannerimage \"$BannerImage\" \
            --title \"${UserInfoTitle}\" \
            --message \"${UserInfoMessage}\" \
            --icon \"${InfoboxIcon}\" \
            --iconsize 198 \
            --liststyle compact \
            ${PromptListArguments} \
            --button1text \"${Install_Button_Custom}\" \
            --button2text \"${Defer_Button_Custom}\" \
            --timer \"${TimePromtUser}\" \
            --infotext \"$scriptVersion\" \
            --ontop \
            --helpmessage \"${helpmessage}\" \
            --titlefont 'shadow=true, size=${Dialog_update_titlefont}' \
            --messagefont 'size=${Dialog_update_messagefont}' \
            --width $Dialog_update_width \
            --height $Dialog_update_height \ "
    else
            PromtUser="$dialogBinary \
            --bannerimage \"$BannerImage\" \
            --title \"${UserInfoTitle}\" \
            --message \"${UserEnforceMessage}\" \
            --icon \"${InfoboxIcon}\" \
            --iconsize 198 \
            --liststyle compact \
            ${PromptListArguments} \
            --button1text \"${Install_Button_Custom}\" \
            --infotext \"$scriptVersion\" \
            --ontop \
            --helpmessage \"${helpmessage}\" \
            --titlefont 'shadow=true, size=${Dialog_update_titlefont}' \
            --messagefont 'size=${Dialog_update_messagefont}' \
            --width $Dialog_update_width \
            --height $Dialog_update_height \ "
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
if system_profiler SPPowerDataType | grep -q "Battery Power"
    then
        icon="SF=laptopcomputer.and.arrow.down,weight=semibold,colour1=#ffffff,colour2=#2986cc"
    else
        icon="SF=desktopcomputer.and.arrow.down,weight=semibold,colour1=#ffffff,colour2=#2986cc"
fi

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# "Patch Helper" dialog Settings and Features
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
runUpdates="$dialogBinary \
--bannerimage \"$BannerImage\" \
--title \"${title}\" \
--message \"${message}\" \
--helpmessage \"${helpmessage}\" \
--icon \"$icon\" \
--infobox \"${infobox}\" \
--progress \
--progresstext \"${progresstext}\" \
--button1text \"${button1text_wait}\" \
--button1disabled \
--infotext \"$scriptVersion\" \
--titlefont 'shadow=true, size=${Dialog_update_titlefont}' \
--messagefont 'size=${Dialog_update_messagefont}' \
--width $Dialog_update_width \
--height $Dialog_update_height \
--position '$RunUpdates_Dialog_position' \
--moveable \
--overlayicon \"$InfoboxIcon\" \
--quitkey $Dialog_quitkey \
--commandfile \"$PatchHelperCommandFile\" "

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
# Run command as logged-in user (thanks, @scriptingosx!)
# shellcheck disable=SC2145

function runAsUser() {
    updateScriptLog "Run \"$@\" as \"$loggedInUserID\" … "
    launchctl asuser "$loggedInUserID" sudo -u "$loggedInUser" "$@"
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Update the "Welcome" dialog
function dialogPatchHelper(){
    updateScriptLog "PROMT USER DIALOG: $1"
    echo "$1" >> "$CommandFile"
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Update the "Patch Helper" dialog
function PatchHelper() {
    updateScriptLog "Patch Helper DIALOG: $1"
    echo "$1" >> "$PatchHelperCommandFile"
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Update the "Failure" dialog
function dialogUpdateFailure(){
    updateScriptLog "FAILURE DIALOG: $1"
    echo "$1" >> "$failureCommandFile"
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Finalise User Experience
function finalise(){
    
    jamfProPolicyNameFailures=$(printf '%s\n' "$jamfProPolicyNameFailures")
    
    # Output Line Number in `true` Debug Mode
    if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi
    
    # finalise() is reached only after the update workflow has completed.
    # Therefore, always remove the deferral state and LaunchDaemon on exit,
    # regardless of whether individual updates succeeded or failed.
    # Deferrals and pre-update errors keep cleanupDeferralOnExit=false and
    # therefore continue to preserve the LaunchDaemon.
    cleanupDeferralOnExit="true"
    updateScriptLog "FINALISE: Update workflow completed; deferral state and LaunchDaemon will be removed on exit."
    
    if [[ "${jamfProPolicyTriggerFailure}" == "failed" ]]; then
        updateScriptLog "FINALISE: Update failure detected; cleanup will still be performed after the failure dialog."
        
        Failure_Info_Title=$(/usr/libexec/PlistBuddy -c "Print :Messages:Failure_Info_Title" "$Managed_Preferences" 2>/dev/null)
        Failure_Info_Title="$(printf '%s\n' "$Failure_Info_Title" | /usr/bin/sed "s/%REAL_FIRSTNAME%/${loggedInUserFirstname}/" | /usr/bin/sed "s/%UPDATE_COUNT%/${Update_Count}/")"
        
        Failure_Info_Progresstext=$(/usr/libexec/PlistBuddy -c "Print :Messages:Failure_Info_Progresstext" "$Managed_Preferences" 2>/dev/null)
        Failure_Info_Progresstext="$(printf '%s\n' "$Failure_Info_Progresstext" | /usr/bin/sed "s/%REAL_FIRSTNAME%/${loggedInUserFirstname}/" | /usr/bin/sed "s/%UPDATE_COUNT%/${Update_Count}/")"
        
        Failure_Info_Message=$(/usr/libexec/PlistBuddy -c "Print :Messages:Failure_Info_Message" "$Managed_Preferences" 2>/dev/null)
        Failure_Info_Message="$(printf '%s\n' "$Failure_Info_Message" | /usr/bin/sed "s/%jamfProPolicyNameFailures%/${jamfProPolicyNameFailures}/" | /usr/bin/sed "s/%SUPPORT_EMAIL%/${Support_Email}/" | /usr/bin/sed "s/%REAL_FIRSTNAME%/${loggedInUserFirstname}/")"
        
        
        killProcess "caffeinate"
        
        PatchHelper "title: $Failure_Info_Title"
        PatchHelper "progresstext: $Failure_Info_Progresstext"
        
        PatchHelper "icon: SF=xmark.circle.fill,weight=bold,colour1=#BB1717,colour2=#F31F1F"
        PatchHelper "button1text: OK"
        PatchHelper "button1: enable"
        PatchHelper "progress: reset"
        
        
        # Wait for user-acknowledgment due to detected failure
        wait
        
        dialogFailureCMD="$dialogBinary \
        --moveable \
        --title \"${failureTitle}\" \
        --message \"$Failure_Info_Message\" \
        --icon \"$failureIcon\" \
        --iconsize 125 \
        --width $Dialog_update_width \
        --height $Dialog_update_height \
        --position $Faild_Dialog_position \
        --button1text \"${Faild_Button_Custom}\" \
        --infotext \"$scriptVersion\" \
        --titlefont 'size=${Dialog_update_titlefont}' \
        --messagefont 'size=${Dialog_update_messagefont}' \
        --overlayicon \"$InfoboxIcon\" \
        --commandfile \"$failureCommandFile\" "
        
        PatchHelper "quit:"
        eval "${dialogFailureCMD}" & sleep 0.3
        
        updateScriptLog "\n\n# # #\n# FAILURE DIALOG\n# # #\n"
        updateScriptLog "Jamf Pro Policy Name Failures:"
        updateScriptLog "${jamfProPolicyNameFailures}"
        
            
        #dialogUpdateFailure "message: $Failure_Info_Message"
        dialogUpdateFailure "icon: SF=xmark.circle.fill,weight=bold,colour1=#BB1717,colour2=#F31F1F"
        dialogUpdateFailure "button1text: ${button1textCompletionActionOption}"
        
        # Wait for user-acknowledgment due to detected failure
        wait
        
        dialogUpdateFailure "quit:"
        quitScript "1"
        
    else
        updateScriptLog "FINALISE: Updates completed successfully."
        
        PatchHelper "title: ${final_sucess_titel}"        
        PatchHelper "progresstext: ${final_sucess_progresstext}"
        
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

    lastJamfCommandExitCode=0

    # Output Line Number in `true` Debug Mode
    if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi

    trigger="$1"

    if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]]; then

        updateScriptLog "Patch Helper DIALOG: DEBUG MODE: TRIGGER: $jamfBinary policy -id $trigger"
        if [[ "$trigger" == "recon" ]]; then
            updateScriptLog "Patch Helper DIALOG: DEBUG MODE: RECON: $jamfBinary recon ${reconOptions}"
        fi
        sleep 1
        lastJamfCommandExitCode=0

    elif [[ "$trigger" == "recon" ]]; then

        PatchHelper "listitem: index: $i, status: wait, statustext: Updating …, "
        updateScriptLog "Patch Helper DIALOG: Computer inventory, with the following reconOptions: \"${reconOptions}\", will be be executed in the 'confirmPolicyExecution' function …"
        # eval "${jamfBinary} recon ${reconOptions}"
    else
        updateScriptLog "Patch Helper DIALOG: RUNNING: $jamfBinary policy -id $trigger -forceNoRecon"
        eval "${jamfBinary} policy -id ${trigger} -forceNoRecon"                       # Add comment for policy testing
        lastJamfCommandExitCode=$?
        updateScriptLog "Patch Helper DIALOG: Jamf policy exit code: ${lastJamfCommandExitCode}"
        # eval "${jamfBinary} policy -id ${trigger} -true | tee -a ${scriptLog}"    # Remove comment for policy testing
    fi

}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Confirm Policy Execution
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
function confirmPolicyExecution() {

    # Output Line Number in `true` Debug Mode
    if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi

    trigger="${1}"
    validation="${2}"
    updateScriptLog "Patch Helper DIALOG: Confirm Policy Execution: '${trigger}' '${validation}'"

    case ${validation} in

        */* ) # If the validation variable contains a forward slash (i.e., "/"), presume it's a path and check if that path exists on disk
            if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]]; then
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
            if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]]; then
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
    if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi
    
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
            if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi
            updateScriptLog "Patch Helper DIALOG: Validate Policy Result: ${validation}"

            if [[ "${trigger}" == "recon" ]]; then
                PatchHelper "listitem: index: $i, status: wait, statustext: Updating …, "
                updateScriptLog "Patch Helper DIALOG: Updating computer inventory with the following reconOptions: \"${reconOptions}\" …"

                if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]]; then
                    updateScriptLog "Patch Helper DIALOG: DEBUG MODE: eval ${jamfBinary} recon ${reconOptions}"
                    lastJamfCommandExitCode=0
                else
                    eval "${jamfBinary} recon ${reconOptions}"
                    lastJamfCommandExitCode=$?
                    updateScriptLog "Patch Helper DIALOG: Jamf recon exit code: ${lastJamfCommandExitCode}"
                fi
            fi

            if [[ "${lastJamfCommandExitCode:-1}" -eq 0 ]]; then
                if [[ "${trigger}" == "recon" ]]; then
                    PatchHelper "listitem: index: $i, status: success, statustext: Updated"
                else
                    PatchHelper "listitem: index: $i, status: success, statustext: Installed"
                fi
            else
                PatchHelper "listitem: index: $i, status: fail, statustext: Failed"
                jamfProPolicyTriggerFailure="failed"
                exitCode="1"
                jamfProPolicyNameFailures+="• $listitem  \n"
                updateScriptLog "Patch Helper DIALOG: ERROR: Jamf command failed with exit code ${lastJamfCommandExitCode}."
            fi
        ;;
        
        ###
        # Catch-all
        ###
        
        * )
            # Output Line Number in `true` Debug Mode
            if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi
            updateScriptLog "Patch Helper DIALOG: Validate Policy Results Catch-all: ${validation}"
            PatchHelper "listitem: index: $i, status: error, statustext: Error"
            jamfProPolicyTriggerFailure="failed"
            exitCode="1"
            jamfProPolicyNameFailures+="• $listitem  \n"
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
# Completion Action (i.e., Wait or Quit)
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
function completionAction() {

    if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]]; then
        updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #"
        runAsUser osascript -e 'display dialog "Patch Helper is operating in Debug Mode.\r\r• completionActionOption == '"'"'${completionActionOption}'"'"'\r\r" with title "Patch Helper: Debug Mode" buttons {"Close"} with icon note'
        return 0
    fi

    shopt -s nocasematch

    case ${completionActionOption} in
        "Quit" )
            updateScriptLog "QUIT SCRIPT: Completion action is Quit."
            ;;
        * )
            updateScriptLog "QUIT SCRIPT: Completion action is wait."
            wait
            ;;
    esac

    shopt -u nocasematch
    return 0
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Quit Script
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
function quitScript() {
    local requestedExitCode="${1:-${exitCode:-0}}"
    local cleanupResult=0

    if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]]; then
        updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #"
    fi

    updateScriptLog "QUIT SCRIPT: Exiting with requested exit code ${requestedExitCode} …"

    updateScriptLog "QUIT SCRIPT: Revoke API Token"
    invalidateToken || true

    updateScriptLog "QUIT SCRIPT: De-caffeinate …"
    killProcess "caffeinate"

    if [[ -n "${overlayicon:-}" && -e "$overlayicon" ]]; then
        updateScriptLog "QUIT SCRIPT: Removing ${overlayicon} …"
        /bin/rm -f "$overlayicon"
    fi

    if [[ -n "${CommandFile:-}" && -e "$CommandFile" ]]; then
        updateScriptLog "QUIT SCRIPT: Removing ${CommandFile} …"
        /bin/rm -f "$CommandFile"
    fi

    if [[ -n "${PatchHelperCommandFile:-}" && -e "$PatchHelperCommandFile" ]]; then
        updateScriptLog "QUIT SCRIPT: Removing ${PatchHelperCommandFile} …"
        /bin/rm -f "$PatchHelperCommandFile"
    fi

    if [[ -n "${failureCommandFile:-}" && -e "$failureCommandFile" ]]; then
        updateScriptLog "QUIT SCRIPT: Removing ${failureCommandFile} …"
        /bin/rm -f "$failureCommandFile"
    fi

    if [[ -e /var/tmp/dialog.log ]]; then
        updateScriptLog "QUIT SCRIPT: Removing /var/tmp/dialog.log"
        /bin/rm -f /var/tmp/dialog.log
    fi

    if [[ -n "${plistOutput:-}" && -e "$plistOutput" ]]; then
        updateScriptLog "QUIT SCRIPT: Removing ${plistOutput} …"
        /bin/rm -f "$plistOutput"
    fi

    if [[ -n "${xmlupdates:-}" && -e "$xmlupdates" ]]; then
        updateScriptLog "QUIT SCRIPT: Removing ${xmlupdates} …"
        /bin/rm -f "$xmlupdates"
    fi

    # Perform all user-facing waiting before bootout. ClearUpLaunchDaemon may
    # terminate this process tree when the current Jamf policy was started by it.
    completionAction

    if [[ "$cleanupDeferralOnExit" == "true" ]]; then
        updateScriptLog "QUIT SCRIPT: Completed update workflow; removing deferral state and LaunchDaemon."
        CleanupDeferralState || cleanupResult=1
    else
        updateScriptLog "QUIT SCRIPT: Deferral state and LaunchDaemon are preserved."
    fi

    if [[ $cleanupResult -ne 0 ]]; then
        requestedExitCode=1
    fi

    exit "$requestedExitCode"
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Dialog helpers
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
function waitForDialog() {
    local timeoutSeconds="${1:-30}"
    local checks=0
    local maxChecks=$(( timeoutSeconds * 2 ))

    while ! /usr/bin/pgrep -q -x "Dialog"; do
        if (( checks >= maxChecks )); then
            return 1
        fi

        /bin/sleep 0.5
        ((checks++))
    done

    return 0
}

function startPatchHelperDialog() {
    updateScriptLog "PROMT USER DIALOG: Starting Patch Helper dialog."

    eval "${runUpdates[*]}" &
    PatchHelperProcessID=$!
    /bin/sleep 0.3

    if ! waitForDialog 30; then
        updateScriptLog "PROMT USER DIALOG: ERROR: Patch Helper dialog did not appear within 30 seconds."
        completionActionOption="Quit"
        cleanupDeferralOnExit="false"
        quitScript "1"
    fi

    updateScriptLog "PROMT USER DIALOG: 'Patch Helper' dialog displayed; ensure it's the front-most app"
    runAsUser osascript -e 'tell application "Dialog" to activate'
}

function deferAndQuit() {
    local reason="$1"
    local previousDeferralValue="$CurrentDeferralValue"
    local nextDeferralValue=$(( CurrentDeferralValue - 1 ))

    updateScriptLog "PROMT USER DIALOG: Deferral requested (${reason})."
    updateScriptLog "PROMT USER DIALOG: Deferral counter ${previousDeferralValue} -> ${nextDeferralValue}."

    if ! setDeferralCount "$BundleIDDeferral" "$nextDeferralValue" "$DeferralPlist"; then
        updateScriptLog "PROMT USER DIALOG: ERROR: Could not update deferral counter."
        completionActionOption="Quit"
        cleanupDeferralOnExit="false"
        quitScript "1"
    fi

    CurrentDeferralValue="$nextDeferralValue"

    if EnsureLaunchDaemon; then
        updateScriptLog "PROMT USER DIALOG: Deferral scheduled successfully."
        completionActionOption="Quit"
        cleanupDeferralOnExit="false"
        quitScript "0"
    else
        updateScriptLog "PROMT USER DIALOG: ERROR: Deferral could not be scheduled because the LaunchDaemon is not ready. Restoring deferral counter."
        setDeferralCount "$BundleIDDeferral" "$previousDeferralValue" "$DeferralPlist" || true
        CurrentDeferralValue="$previousDeferralValue"
        completionActionOption="Quit"
        cleanupDeferralOnExit="false"
        quitScript "1"
    fi
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
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
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
if [[ "${UserInformation}" == "promtUserInfo" ]]; then

    if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]]; then
        updateScriptLog "PROMT USER DIALOG: # # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #"
    fi

    eval "${PromtUser}" &
    pid=$!
    /bin/sleep 0.3

    wait "$pid" 2>/dev/null
    promptExitCode=$?
    PromtUser="$promptExitCode"

    updateScriptLog "PROMT USER DIALOG: swiftDialog exit code: ${promptExitCode}"

    case "$promptExitCode" in

        0)
            updateScriptLog "PROMT USER DIALOG: ${loggedInUser} clicked Update."
            updateScriptLog "PROMT USER DIALOG: reconOptions: ${reconOptions}"
            startPatchHelperDialog
            ;;

        2)
            if [[ "$CurrentDeferralValue" -gt 0 ]]; then
                updateScriptLog "PROMT USER DIALOG: ${loggedInUser} deferred the update."
                deferAndQuit "button2"
            else
                updateScriptLog "PROMT USER DIALOG: Exit code 2 received but no deferrals remain; enforcing updates."
                updateScriptLog "PROMT USER DIALOG: reconOptions: ${reconOptions}"
                startPatchHelperDialog
            fi
            ;;

        3)
            updateScriptLog "PROMT USER DIALOG: Info action closed the prompt; no update workflow started."
            osascript -e "set Volume 3"
            afplay /System/Library/Sounds/Glass.aiff
            completionActionOption="Quit"
            cleanupDeferralOnExit="false"
            quitScript "0"
            ;;

        4)
            updateScriptLog "PROMT USER DIALOG: ${loggedInUser} allowed the timer to expire."
            if [[ "$CurrentDeferralValue" -gt 0 ]]; then
                deferAndQuit "timer"
            else
                updateScriptLog "PROMT USER DIALOG: Timer expired but no deferrals remain; enforcing updates."
                startPatchHelperDialog
            fi
            ;;

        *)
            updateScriptLog "PROMT USER DIALOG: Unexpected swiftDialog exit code: ${promptExitCode}"
            completionActionOption="Quit"
            cleanupDeferralOnExit="false"
            quitScript "1"
            ;;

    esac

else

    if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]]; then
        updateScriptLog "PROMT USER DIALOG: # # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #"
    fi

    startPatchHelperDialog

fi

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Iterate through policyJSON to construct the list for swiftDialog
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Output Line Number in `true` Debug Mode
if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi

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
if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi

totalProgressSteps=$(get_json_value "${policyJSON}" "steps.length")
progressIncrementValue=$(( 100 / totalProgressSteps ))
updateScriptLog "Patch Helper DIALOG: Total Number of Steps: ${totalProgressSteps}"
updateScriptLog "Patch Helper DIALOG: Progress Increment Value: ${progressIncrementValue}"
  

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# The ${array_name[*]/%/,} expansion will combine all items within the array adding a "," character at the end
# To add a character to the start, use "/#/" instead of the "/%/"
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Output Line Number in `true` Debug Mode
if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi

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
if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi

updateScriptLog "Patch Helper DIALOG: Initial progress bar"
PatchHelper "progress: 1"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Close PROMT USER DIALOG
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Output Line Number in `true` Debug Mode
if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi

dialogPatchHelper "quit:"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Update Patch Helper's infobox
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# Output Line Number in `true` Debug Mode
if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi
    
computerName=$(scutil --get ComputerName)


infobox=""
if [[ -n ${computerName} ]]; then infobox+="**Computer Name:**  \n$computerName  \n\n" ; fi
if [[ -n ${Update_Count} ]]; then infobox+="**Updates:** $Update_Count  \n\n" ; fi

PatchHelper "infobox: ${infobox}"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# This for loop will iterate over each distinct step in the policyJSON
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
for (( i=0; i<dialog_step_length; i++ )); do 

    # Output Line Number in `true` Debug Mode
    if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi

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
if [[ "${debugMode}" == "true" ]] || [[ "${debugMode}" == "verbose" ]]; then updateScriptLog "# # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi

finalise
