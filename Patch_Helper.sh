#!/bin/bash
#######################################################################
# Shellscript		:	Patch Helper
# Edetiert durch	:	Andreas Vogel
# Changelog			: 	0.1 -	initial skript
#                   :   0.2 -   Termination of the LaunchDaemon via bootout
#                   :   0.3 -   Retrieve customization of PolicyNames via API
#                   :   0.4 -   Adjustment of the icons so that they use the correct icon in the "case" function
#                   :   0.5 -   Adjustment of the JSON so that it always executes the policy for Update Inventory at the end..
#                   :   0.6 -   Added function for "invalidateToken" so that the token is automatically discarded on exit.
#                   :   0.7 -   Customization of the icon 
#                   :   0.8 -   Safari 
#					:	0.9 -	Translation, Redigatur
#                   :   0.9.1 -   Counter is changed as $Update_Count so that only the number of updates is displayed and
#                               no longer the number of all steps (incl. the update inventory)
#
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
scriptVersion="1.0.0"
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
scriptLog="/var/log/it.next_patch_management.log"


if [[ ! -f "${scriptLog}" ]]; then
    touch "${scriptLog}"
fi

debugMode="${4:-"true"}"                                  # Parameter 4: Debug Mode [ true (default) | false ]

BannerImage="${5}"                                        # Parameter 5: BannerImage on Top of swiftDialog
if [[ -z "$BannerImage" ]]; then
    #BannerImage="https://ics.services.jamfcloud.com/icon/hash_bf163c243eda9edd20bd269277da921353f1927b3f1d5f12df92c2879d827336"
    BannerImage="https://ics.services.jamfcloud.com/icon/hash_cfbe99281c08b7ef85da92dcb56be11a6ff8562e37d24bb20ecf230495d617df"
fi

InfoboxIcon="${6}"                                        # Parameter 6: InfoboxIcon Icon on left Site of swiftDialog
if [[ -z "$InfoboxIcon" ]]; then
    #InfoboxIcon="https://ics.services.jamfcloud.com/icon/hash_512ac7293a7ac36ed21e4f4a10f1508b431cff5183d713df610312e17eeda3d7"
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
    updateScriptLog "WARM-UP: Current Logged-in User: ${loggedInUser}"
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

        updateScriptLog "WARM-UP: Dialog not found. Installing..."

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
            updateScriptLog "WARM-UP: swiftDialog version ${dialogVersion} installed; proceeding..."

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

        updateScriptLog "WARM-UP: swiftDialog version $(/usr/local/bin/dialog --version) found; proceeding..."

    fi

}

if [[ ! -e "/Library/Application Support/Dialog/Dialog.app" ]]; then
    dialogCheck
else
    updateScriptLog "WARM-UP: swiftDialog version $(/usr/local/bin/dialog --version) found; proceeding..."
fi


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

DeferralPlist="/Library/Application Support/JAMF/it.next.update.deferrals.plist"
BundleID="it.next.PatchHelper"
DeferralType="count"

CurrentDeferralValue="$(/usr/libexec/PlistBuddy -c "print :$BundleID:count" "$DeferralPlist" 2>/dev/null)"
# Set up the deferral value if it does not exist already
if [[ -z "$CurrentDeferralValue" ]] || [[ "$CurrentDeferralValue" =~ "File Doesn't Exist" ]]; then
    setDeferral "$BundleID" "$DeferralType" "$UpdateDeferral_Value" "$DeferralPlist"
    CurrentDeferralValue="$(/usr/libexec/PlistBuddy -c "print :$BundleID:count" "$DeferralPlist" 2>/dev/null)"
fi
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# WARM-UP: Complete
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

updateScriptLog "WARM-UP: Complete"

# # # # # # # # # # # # # # # # # # # # User Language # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Function ClearUp the LaunchDaemon 
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
function ClearUpLaunchDaemon() {
    updateScriptLog "Patch Helper DIALOG: Stopping LaunchDaemon launchctl bootout system …"
    launchctl bootout system/it.next.UpdateEnforce
    
    if [ $? -ne 0 ]; then
        updateScriptLog "Patch Helper DIALOG: Error unloading LaunchDaemon"
    else
        updateScriptLog "Patch Helper DIALOG: LaunchDaemon unloaded successfully"
    fi
    
    updateScriptLog "Patch Helper DIALOG: delete the LaunchDaemon so that it is loaded again after a reboot... "
    rm -rf /Library/LaunchDaemons/it.next.UpdateEnforce.plist
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Function ClearUp deferral plist 
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
function ClearUpPlist() {
    updateScriptLog "Patch Helper DIALOG: Deleting plist …"
    rm -rf "/Library/Application Support/JAMF/it.next.update.deferrals.plist"
    
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Function check if deferel are allredy createt  
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
function CheckDeferral() {
    # Check if the daemon exists and is loaded
    if launchctl list | grep -q "it.next.UpdateEnforce"
    then
        updateScriptLog "Patch Helper DIALOG: The daemon exists and is loaded …"
    else
        updateScriptLog "Patch Helper DIALOG: no deferral has been set up yet. Set up the daemon …"
        createLaunchDaemon
        StartLaunchDaemon
    fi
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Function check if deferel are allredy createt  
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
function ClearUpDeferral() {
    # Check if the daemon exists and is loaded
    if launchctl list | grep -q "it.next.UpdateEnforce"
    then
        updateScriptLog "Patch Helper DIALOG: Clean up the daemon, updates were successfully installed …"
        ClearUpLaunchDaemon
        ClearUpPlist
    else
        updateScriptLog "Patch Helper DIALOG: Daemon was not set up, user had not yet moved …"
        ClearUpPlist
    fi
    
}


CurrentUser=$(/usr/sbin/scutil <<< "show State:/Users/ConsoleUser" | /usr/bin/awk -F': ' '/[[:space:]]+Name[[:space:]]:/ { if ( $2 != "loginwindow" ) { print $2 }}')
Language=$(/usr/libexec/PlistBuddy -c 'print AppleLanguages:0' "/Users/$3/Library/Preferences/.GlobalPreferences.plist")

if [[ $Language != de* ]]; then
    UserLanguage="EN"
else
    UserLanguage="DE"
fi

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#
# Create Update List
#
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

udid=$(system_profiler SPHardwareDataType | grep UUID | awk '" " { print $NF }')

xsltFile="/tmp/xsltTemplate.xsl"
xmlFile="/tmp/fileName.xml"
xmlupdates="/tmp/updates.xml"

# Setzen der Icon-Variablen
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Google_Chrome="https://ics.services.jamfcloud.com/icon/hash_94f8d7f60fe82fb234065e05cccf385b1a4f9763ea1b4a3d9737e6a980fd0eae"
Google_Chrome_validation="/Applications/Google Chrome.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Microsoft_Outlook="https://ics.services.jamfcloud.com/icon/hash_b96ae8bdcb09597bff8b2e82ec3b64d0a2d17f33414dbd7d9a48e5186de7fd93"
Microsoft_Outlook_validation="/Applications/Microsoft Outlook.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Slack="https://ics.services.jamfcloud.com/icon/hash_a1ecbe1a4418113177cc061def4996d20a01a1e9b9adf9517899fcca31f3c026"
Slack_validation="/Applications/Slack.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Company_Portal="https://ics.services.jamfcloud.com/icon/hash_2af383e90f870e948ec2d03a5910af1b27fe2b32d7c757848db0fdecfea2ef71"
Company_Portal_validation="/Applications/Company Portal.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Mozilla_Firefox="https://ics.services.jamfcloud.com/icon/hash_b50bdee2e72b3f98cd7cfe8da06a3d5f405507ca0dca2f5f408978f4f24fee0c"
Mozilla_Firefox_validation="/Applications/Firefox.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
GitHub_Desktop="https://ics.services.jamfcloud.com/icon/hash_e7790b367556baee89ffb70d7d545b4cf78698e84cf646777a7d9058762bf69d"
GitHub_Desktop_validation="/Applications/GitHub Desktop.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
iTerm2="https://ics.services.jamfcloud.com/icon/hash_85951b4b7b290fa90d8b3a4d7b652316acb5dac44ebce95e7a00a38879710cc6"
iTerm2_validation="/Applications/iterm.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Microsoft_Edge="https://ics.services.jamfcloud.com/icon/hash_f1fa00c7d8b4cb4d3c58d98c0b0bdbe719a56be39f8b6445ed3df9c8219a126d"
Microsoft_Edge_validation="/Applications/Microsoft Edge.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Microsoft_Excel="https://ics.services.jamfcloud.com/icon/hash_721a7bf38cec7552ecd6ffaee9a0ed2ab21b2318639c23082250be12517fca1c"
Microsoft_Excel_validation="/Applications/Microsoft Excel.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Microsoft_OneNote="https://ics.services.jamfcloud.com/icon/hash_a10ac257accff5479d467cf0c8f148559b92eb0ccb7c78f80464901532c95bdb"
Microsoft_OneNote_validation="/Applications/Microsoft OneNote.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Microsoft_PowerPoint="https://ics.services.jamfcloud.com/icon/hash_9f13ca0d3ab7939d3147fbdea116fbdd94f6716a27292505231a8e93f6307fd6"
Microsoft_PowerPoint_validation="/Applications/Microsoft PowerPoint.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Microsoft_Remote_Desktop="https://ics.services.jamfcloud.com/icon/hash_accfb8273af78d6e2f456a9e3ea882267f82e99c13f9e515d374ffd749aba082"
Microsoft_Remote_Desktop_validation="/Applications/Microsoft Remote Desktop.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Microsoft_Teams="https://ics.services.jamfcloud.com/icon/hash_623505d45ca9c2a1bd26f733306e30cd3fcc1cc0fd59ffc89ee0bfcbfbd0b37e"
Microsoft_Teams_validation="/Applications/Microsoft Teams.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Microsoft_Word="https://ics.services.jamfcloud.com/icon/hash_a4686ab0e2efa2b3c30c42289e3958e5925b60b227ecd688f986d199443cc7a7"
Microsoft_Word_validation="/Applications/Microsoft Word.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Postman="https://ics.services.jamfcloud.com/icon/hash_019df97f436478ca2b98e3f858eb95d4a527a353029df0384f5b8f18dbd0c61d"
Postman_validation="/Applications/postman.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Support_App="https://ics.services.jamfcloud.com/icon/hash_6a2b5ed3a7762b7641b837fd5cc0a5541462f27ec43126db2d4e8dbdcc298f6d"
Support_App_validation="/Applications/Support.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
TeamViewer="https://ics.services.jamfcloud.com/icon/hash_ccbb12778c38f0e2c245a712e78d417930c5d599f44832be9bbee1705f69d3e4"
TeamViewer_validation="/Applications/TeamViewer.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Visual_Studio_Code="https://ics.services.jamfcloud.com/icon/hash_011955c4065d9215a82905984bd200f224c8b3736e3fb947ba64b6fa28b0c02a"
Visual_Studio_Code_validation="/Applications/Visual Studio Code.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Zoom="https://ics.services.jamfcloud.com/icon/hash_92b8d3c448e7d773457532f0478a428a0662f694fbbfc6cb69e1fab5ff106d97"
Zoom_validation="/Applications/zoom.us.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Password="https://ics.services.jamfcloud.com/icon/hash_274cae31e3447da5b641ecd0dcd3ae6d27e7aa24e4aff112f54e9047f9711aa7"
Password_validation="/Applications/1Password.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Adobe_Creative_Cloud_Desktop="https://ics.services.jamfcloud.com/icon/hash_2035ad1a48acb00d5a808cc6daa61c99d03eb2316c39864ba9cdd988fdd73140"
Adobe_Creative_Cloud_Desktop_validation="/Applications/Utilities/Adobe Creative Cloud/ACC/Creative Cloud.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
AppCleaner="https://euc1.ics.services.jamfcloud.com/icon/hash_c304da7fe44e5ab4241d909a1051ae44e9af7d7694ed8dbc53f4d53e6dd0c1f6"
AppCleaner_validation="/Applications/AppCleaner.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Balsamiq_Wireframes="https://euc1.ics.services.jamfcloud.com/icon/hash_2aacaa75080df809d095065d9fd5ac25066d1bfe90eec277f1834e82d44a555a"
Balsamiq_Wireframes_validation="/Applications/Balsamiq Wireframes.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Blender="https://ics.services.jamfcloud.com/icon/hash_d1420bec7e93fc1197c999f499ff1743764ac17789bee60f5466569e83fc7fab"
Blender_validation="/Applications/blender.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Cyberduck="https://euc1.ics.services.jamfcloud.com/icon/hash_d807ad9581dffc5e7317c5b301104a43b37ceca866b36799053412ef327264b8"
Cyberduck_validation="/Applications/Cyberduck.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
DisplayLink_Manager="https://ics.services.jamfcloud.com/icon/hash_ed6f88bfb07d71e245f6b3d69574467f7089ef39d9a98f5d5d770b314706b460"
DisplayLink_Manager_validation="/Applications/DisplayLink Manager.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
DropBox="https://euc1.ics.services.jamfcloud.com/icon/hash_e6361d9d6f2867bf1f939fb9fbe5b7f785413b17dd9d36331e02c3f42f1a3a07"
DropBox_validation="/Applications/Dropbox.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
EasyFind="https://ics.services.jamfcloud.com/icon/hash_a7ad6e3e43ee50fcb73d3e26fd29146906681a6f048a3d305b4857f3165298f5"
EasyFind_validation="/Applications/EasyFind.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Figma="https://ics.services.jamfcloud.com/icon/hash_ad7d074540cf041f9d9857ecf6c0223e38fb8e582168484b97ae95bd7b5a53de"
Figma_validation="/Applications/Figma.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Filezilla="https://euc1.ics.services.jamfcloud.com/icon/hash_b2aa33567e5b48be41e5165c6f02eac485710e041367a685be5bbc97b265229b"
Filezilla_validation="/Applications/FileZilla.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
ImageOptim="https://euc1.ics.services.jamfcloud.com/icon/hash_5dcd3a597ee4fd5b52e63ee0e5f86d97352d281398ee4e91d45abc75e292e086"
ImageOptim_validation="/Applications/imageoptim.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Keka="https://ics.services.jamfcloud.com/icon/hash_b2f82bb89f6e69834dec02b0f12ce6180fbdc1352494adf10d7e7a7aa65c85e6"
Keka_validation="/Applications/Keka.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Microsoft_Skype_for_Business="https://ics.services.jamfcloud.com/icon/hash_a0bb8ab7d90a958892febf03aea84f3b090c2dc0ea9305f7d17f27d622bfbb9e"
Microsoft_Skype_for_Business_validation="/Applications/Skype for Business.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Miro="https://euc1.ics.services.jamfcloud.com/icon/hash_89d42f52cebdbb0862c2229254074da1b31dc334c984031a6ccfc5f46141a569"
Miro_validation="/Applications/Miro.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Sketch="https://euc1.ics.services.jamfcloud.com/icon/hash_32f378b2490f45b03042fc8a388dbc433e7e2e4c2c68b697e3c9647fcd217e44"
Sketch_validation="/Applications/Sketch.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
The_Unarchiver="https://ics.services.jamfcloud.com/icon/hash_5ef15847e6f8b29cedf4e97a468d0cb1b67ec1dcef668d4493bf6537467a02c2"
The_Unarchiver_validation="/Applications/The Unarchiver.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
VLC="https://ics.services.jamfcloud.com/icon/hash_2b428c169b78204f03cff3b040b2b5c428eac9288108e11d43aca994d5bd39f0"
VLC_validation="/Applications/VLC.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Zeplin="https://euc1.ics.services.jamfcloud.com/icon/hash_8d184c2fc82089ed7790429560eee153f79795076999a6d2eef2d9ebcfc9b8d9"
Zeplin_validation="/Applications/Zeplin.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Safari="https://ics.services.jamfcloud.com/icon/hash_4de54603be986c87a1e08401c3077f943388a0f2728c794253c8647e1a234b8f"
Safari_validation="None"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Adobe_Acrobar_Reader="https://ics.services.jamfcloud.com/icon/hash_d5f7f524284ff4ab5671cd5c92ef3938eea192ca4089e0c8b2692f49c5cfe47c"
Adobe_Acrobar_Reader_validation="/Applications/Adobe Acrobat Reader.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Anydesk="https://ics.services.jamfcloud.com/icon/hash_753118b231372bdecc36d637d85c1ebc65e306f341a6d18df4adef72a60aae8d"
Anydesk_validation="/Applications/AnyDesk.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Audacity="https://ics.services.jamfcloud.com/icon/hash_48856b6517bf045e425982abe4d4d036ba8d64ec4f83344cec88f19d3644053f"
Audacity_validation="/Applications/Audacity.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
balenaEtcher="https://ics.services.jamfcloud.com/icon/hash_c55e8e1eb9cdf4935385f77f2440784d28a111df750b9661c7cf20ec4806df3d"
balenaEtcher_validation="/Applications/balenaEtcher.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Clipy="https://ics.services.jamfcloud.com/icon/hash_69311ae3c55874b8c4a75698ea955d2be8169c132303b267de7c2610a5691946"
Clipy_validation="/Applications/Clipy.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Drawio="https://ics.services.jamfcloud.com/icon/hash_fe1fe76b17903b7bdde014647234bc1afab379f375d61ef3844bfeca5f60cd74"
Drawio_validation="/Applications/draw.io.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Keeping_you_Awake="https://ics.services.jamfcloud.com/icon/hash_01bb3a85ce1165f3a6284dd032271778ca3b89380187ab1729188ad625e4d1ca"
Keeping_you_Awake_validation="/Applications/KeepingYouAwake.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Monitor_Control="https://ics.services.jamfcloud.com/icon/hash_09cfa66f17687de4177ec619924110cb0985da70c9ccfcba47944c59c65d4ea2"
Monitor_Control_validation="/Applications/MonitorControl.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
OmniGraffle_7="https://ics.services.jamfcloud.com/icon/hash_af797387cce835f0c01b4514c78b7a87e7889a272ad7ed5a100ec6f82661fe94"
OmniGraffle_7_validation="/Applications/OmniGraffle.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Rectangle="https://ics.services.jamfcloud.com/icon/hash_656b155e64d443182726fe264ac2d7d31295ec7529b5f28afcd04eb1599c9253"
Rectangle_validation="/Applications/Rectangle.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Sourcetree="https://ics.services.jamfcloud.com/icon/hash_176409e6a4b5ca1bc4cf2b0b98e03a87701adf56a1cf64121284786e30e4721f"
Sourcetree_validation="/Applications/Sourcetree.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Zulip="https://ics.services.jamfcloud.com/icon/hash_4ae4efbb4993900bbac7b3fc0e298e804b37730e0e83f1ccb1dbf4fd79bb1c8e"
Zulip_validation="/Applications/Zulip.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Go_to_Meeting="https://ics.services.jamfcloud.com/icon/hash_03e38ad91467fca7875becc5cec5141358ac013cb0ead27145653673324efb0a"
Go_to_Meeting_validation="/Applications/GoToMeeting.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
GIMP="https://ics.services.jamfcloud.com/icon/hash_db1f5181e6c32c57e0d7e777fa392c870552172ac5c5316a0618f94b4ebd1a94"
GIMP_validation="/Applications/GIMP.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Apache_Directory_Studio="https://ics.services.jamfcloud.com/icon/hash_5497c297450e6e5a60a1ed540e82759c1c41d9b8c3e0774f8805b8f8e78101fe"
Apache_Directory_Studio_validation="/Applications/ApacheDirectoryStudio.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Azure_Data_Studio="https://ics.services.jamfcloud.com/icon/hash_967faf08185090d670b1fbaeec5243431d5ccadd508abbae5f4cbd9279876a6c"
Azure_Data_Studio_validation="/Applications/Azure Data Studio.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Docker="https://ics.services.jamfcloud.com/icon/hash_34da3317712f203f9d80ce968304d0a490900e68ab7986a79c4a290f4d63a9af"
Docker_validation="/Applications/Docker.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Meld="https://ics.services.jamfcloud.com/icon/hash_7635c2f1f8439aa3b129a9db0755dae6a0d76f141e1afa2252e0020f5214ee8e"
Meld_validation="/Applications/Meld.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
PyCharm="https://ics.services.jamfcloud.com/icon/hash_3f93975114b0199f0bd1baf116db1549f87f5b0165f03df5014edda3ff365f7a"
PyCharm_validation="/Applications/PyCharm.app/Contents/Info.plist"
#* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
SquidMan="https://ics.services.jamfcloud.com/icon/hash_a89c20c9145dfa733c425e7c121e503ed270348ffcce255f4837aca001949dab"
SquidMan_validation="/Applications/SquidMan.app/Contents/Info.plist"
#* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
TNEFs_Enough="https://ics.services.jamfcloud.com/icon/hash_302941a1fa63b8289b2bbabfdddb7056d67f83e8913d234c1833e15e3a012602"
TNEFs_Enough_validation="/Applications/TNEF's Enough.app/Contents/Info.plist"
#* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Wireshark="https://ics.services.jamfcloud.com/icon/hash_1f874fcf121ba5028ee8740a8478fda171fe85d778fda72b93212af78290f8f3"
Wireshark_validation="/Applications/Wireshark.app/Contents/Info.plist"
#* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Jabra_Direct="https://ics.services.jamfcloud.com/icon/hash_7207235148a8c306ac40e3248dfa7e74ccbb912562ab2b18d98d151a35e038c2"
Jabra_Direct_validation="/Applications/Jabra Direct.app/Contents/Info.plist"
#* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
SimpleMind_Pro="https://ics.services.jamfcloud.com/icon/hash_d23a5a8752af9e4de9b960850118ef8f85cd5ae4c742ff7f839792f795153f04"
SimpleMind_Pro_validation="/Applications/SimpleMind Pro.app/Contents/Info.plist"
#* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Tunnelblick="https://ics.services.jamfcloud.com/icon/hash_0ff661450177e85368cc22c97703c73d2e13b161e7289c440faeafcea0389bfd"
Tunnelblick_validation="/Applications/Tunnelblick.app/Contents/Info.plist"
#* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
UTM="https://ics.services.jamfcloud.com/icon/hash_d51d14a3397054293dd5591df171a6f37825093f89dbe8f03191fd024e0c0ddc"
UTM_validation="/Applications/UTM.app/Contents/Info.plist"
#* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Bitwarden="https://ics.services.jamfcloud.com/icon/hash_4eb5da16820a8d37cc5918213323b5d2ae2bdb1cfed104d84535299123acab18"
Bitwarden_validation="/Applications/Bitwarden.app/Contents/Info.plist"
#* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
Brave="https://euc1.ics.services.jamfcloud.com/icon/hash_d07ef04ebf5d9a509070858a26c39fd99feef114422de934973b6b19cb565a6c"
Brave_validation="/Applications/Brave Browser.app/Contents/Info.plist"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
placeholder_icon="https://ics.services.jamfcloud.com/icon/hash_ff2147a6c09f5ef73d1c4406d00346811a9c64c0b6b7f36eb52fcb44943d26f9"
placeholder_validation="None"
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #

/bin/cat <<EOF > "$xsltFile"
<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="text"/>
<xsl:template match="/">
<xsl:for-each select="computer_management/policies/policy">
<xsl:value-of select="id"/>
<xsl:text> </xsl:text>
<xsl:value-of select="name"/>
<xsl:text> </xsl:text>
<xsl:value-of select="triggers"/>
<xsl:text> </xsl:text>
<xsl:text>&#xa;</xsl:text>
</xsl:for-each>
</xsl:template>
</xsl:stylesheet>
EOF

authToken=$(/usr/bin/curl "${jamfpro_url}/api/v1/auth/token" --silent --request POST --header "Authorization: Basic ${encodedCredentials}")

if [[ $(/usr/bin/sw_vers -productVersion | awk -F . '{print $1}') -lt 12 ]]
then
api_token=$(/usr/bin/awk -F \" 'NR==2{print $4}' <<< "$authToken" | /usr/bin/xargs)
else
api_token=$(/usr/bin/plutil -extract token raw -o - - <<< "$authToken")
fi
    
/usr/bin/curl -X GET "$jamfpro_url/JSSResource/computermanagement/udid/$udid/subset/policies" -H "accept: application/xml" -H "Authorization: Bearer ${api_token}" | xsltproc "$xsltFile" - > $xmlFile

Update_Count=$(grep -c "patch_app_updates" "$xmlFile")
sed '/patch_app_updates/!d' $xmlFile > $xmlupdates
IDs=($(awk '{ print $1 }' $xmlupdates))


# Prüfen, ob ein Update für Safari bereitsteht
Safari_update=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist RecommendedUpdates | grep -o 'Safari')

if [[ -n "$Safari_update" ]]; then
    SafariUpdate="true"
    ((Update_Count++))
else
    SafariUpdate="false"
fi


function GetPolicyName() {
    PolicyName=$(/usr/bin/curl --tlsv1.2 -H "Accept: application/xml" -H "Authorization: Bearer ${api_token}" "${jamfpro_url}/JSSResource/policies/id/$1" | xmllint --xpath '/policy/general/name/text()' - 2>/dev/null)
    echo "$PolicyName"
}

function invalidateToken() {
    responseCode=$(curl -w "%{http_code}" -H "Authorization: Bearer ${api_token}" $jamfpro_url/api/v1/auth/invalidate-token -X POST -s -o /dev/null)
    if [[ ${responseCode} == 204 ]]
        then
            updateScriptLog "QUIT SCRIPT: Token successfully invalidated"
        
    elif [[ ${responseCode} == 401 ]]
        then
            updateScriptLog "QUIT SCRIPT: Token already invalid"
            
        else
            updateScriptLog "An unknown error occurred invalidating the token"
    
    fi
}

appnames_display=$(cat $xmlupdates | sed 's/[0-9]*//g' | sed 's/ patch_app_updates/,/g')
Names_display=($(printf "%s\n" "${appnames_display[@]}"))

if [[ "$Update_Count" -eq 1 ]]; then
    Plural_EN=""
    Plural_DE=""
    pluralQuantity_DE="ist"
    
elif [[ "$Update_Count" -gt 1 ]]; then
    Plural_EN="s" 
    Plural_DE="s"
    pluralQuantity_DE="sind"
else
    echo "no patches found, exiting"
    ClearUpDeferral
    exit 0
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
PatchHelperCommandFile=$( mktemp /var/tmp/dialogSetupYourMac.XXX )
failureCommandFile=$( mktemp /var/tmp/dialogFailure.XXX )
jamfBinary="/usr/local/bin/jamf"

# # # # # # # # # # # # # # # # # # # "Patch Helper" Change Time Value # # # # # # # # # # # # # # # #
if [[ $StartInterval -eq 3600 ]]; then
        echo "Das Update wird stündlich ausgeführt."
        Time_EN="hourly"
        Time_DE="stündlich"
elif [[ $StartInterval -lt 3600 ]]; then
        # Converted interval in minutes
        intervalMinutes=$((StartInterval / 60))
        echo "Das Update wird alle $intervalMinutes Minuten ausgeführt."
        Time_EN="all $intervalMinutes minutes"
        Time_DE="alle $intervalMinutes Minuten"
else
        # Converted interval in hours and minutes
        intervalHours=$((StartInterval / 3600))
        intervalMinutes=$(( (StartInterval % 3600) / 60 ))
        echo "Das Update wird alle $intervalHours Std. $intervalMinutes Min erzwungen."
        Time_EN="all $intervalHours Hours $intervalMinutes minutes"
        Time_DE="jede $intervalHours Stunde und $intervalMinutes Minuten"
fi

Time=Time_${UserLanguage}


# # # # # # # # # # # # # # # # # # # "Patch Helper" dialog Title, Messages # # # # # # # # # # # # # # # #
UserInfoTitle_DE="Hey ${loggedInUserFirstname}, es $pluralQuantity_DE ${Update_Count} Update${!Plural} verfügbar."
UserInfoTitle_EN="Hello ${loggedInUserFirstname}, there $pluralQuantity_EN ${Update_Count} update${!Plural} available."
    
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
UserInfoMessage_DE="Die folgenden Programme werden aktualisiert: \n\n${Names_display[*]} \n\n--- \nWährend der Installation werden sie geschlossen. Bitte klicke auf **Update**, um mit der Aktualisierung zu beginnen. \n\n#### Verbleibende Anzahl an Verschiebungen: $CurrentDeferralValue \n\nDieser Dialog wird Dich **${!Time}** erinnern, bis die maximale Verschiebung der Updates erreicht ist."

UserInfoMessage_EN="The following applications are updated: \n\n${Names_display[*]} \n\n--- \nDuring the installation the affected applications will be closed. Please click **Update** to start the update. \n\n#### Remaining number of moves: $CurrentDeferralValue \n\nUnless you apply the updates, this dialog **${!Time}** will remind you until the number reaches **0**."
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
        "blurscreen" : "false",
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
        "blurscreen" : "false",
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

IconServicePrefixUrl="https://ics.services.jamfcloud.com/icon/hash_"

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
function UpdateJSONConfiguration() {
    
    # Output Line Number in `true` Debug Mode
    if [[ "${debugMode}" == "true" ]]; then updateScriptLog "PROMT USER DIALOG: # # # Patch Helper true DEBUG MODE: Line No. ${LINENO} # # #" ; fi
    
    updateScriptLog "PROMT USER DIALOG: PolicyJSON Configuration: $Updates"
            
            policyJSON='{
    "steps": ['
            
            
    for ((i = 0; i < ${#IDs[@]}; i++)); do
        PolicyName=$(GetPolicyName "${IDs[i]}")
        
                # Setzen des Icons basierend auf dem App-Namen
                case $PolicyName in
                    *Google_Chrome* | *Chrome*)
                        icon=$Google_Chrome
                        validation=$Google_Chrome_validation
                    ;;
                    *Microsoft_Outlook* | *Outlook*)
                        icon=$Microsoft_Outlook
                        validation=$Microsoft_Outlook_validation
                    ;;
                    *Slack*)
                        icon=$Slack
                        validation=$Slack_validation
                    ;;
                    *Company_Portal* | *Company\ Portal*)
                        icon=$Company_Portal
                        validation=$Company_Portal_validation
                    ;;
                    *Mozilla_Firefox* | *Firefox* )
                        icon=$Mozilla_Firefox
                        validation=$Mozilla_Firefox_validation
                    ;;
                    *GitHub_Desktop* | *GitHub\ Desktop*)
                        icon=$GitHub_Desktop
                        validation=$GitHub_Desktop_validation
                    ;;
                    *iTerm2*)
                        icon=$iTerm2
                        validation=$iTerm2_validation
                    ;;
                    *Microsoft_Edge* | *Microsoft\ Edge* | *Edge*)
                        icon=$Microsoft_Edge
                        validation=$Microsoft_Edge_validation
                    ;;
                    *Microsoft_Excel* | *Microsoft\ Excel* | *Excel* )
                        icon=$Microsoft_Excel
                        validation=$Microsoft_Excel_validation
                    ;;
                    *Microsoft_OneNote* | *Microsoft\ OneNote* | *OneNote*)
                        icon=$Microsoft_OneNote
                        validation=$Microsoft_OneNote_validation
                    ;;
                    *Microsoft_PowerPoint* | *Microsoft\ PowerPoint* | *PowerPoint*)
                        icon=$Microsoft_PowerPoint
                        validation=$Microsoft_PowerPoint_validation
                    ;;
                    *Microsoft_Remote_Desktop* | *Microsoft\ Remote\ Desktop*)
                        icon=$Microsoft_Remote_Desktop
                        validation=$Microsoft_Remote_Desktop_validation
                    ;;
                    *Microsoft_Teams* | *Microsoft\ Teams* | *Teams*)
                        icon=$Microsoft_Teams
                        validation=$Microsoft_Teams_validation
                    ;;
                    *Microsoft_Word* | *Word*)
                        icon=$Microsoft_Word
                        validation=$Microsoft_Word_validation
                    ;;
                    *Postman*)
                        icon=$Postman
                        validation=$Postman_validation
                    ;;
                    *Support_App* | *Support\ App*)
                        icon=$Support_App
                        validation=$Support_App_validation
                    ;;
                    *TeamViewer* | *Teamviewer*)
                        icon=$TeamViewer
                        validation=$TeamViewer_validation
                    ;;
                    *Visual_Studio_Code* | *Visual\ Studio\ Code*)
                        icon=$Visual_Studio_Code
                        validation=$Visual_Studio_Code_validation
                    ;;
                    *Zoom*)
                        icon=$Zoom
                        validation=$Zoom_validation
                    ;;
                    *Zeplin*)
                        icon=$Zeplin
                        validation=$Zeplin_validation
                    ;;
                    *VLC*)
                        icon=$VLC
                        validation=$VLC_validation
                    ;;
                    *The_Unarchiver* | *The\ Unarchiver*)
                        icon=$The_Unarchiver
                        validation=$The_Unarchiver_validation
                    ;;
                    *Sketch*)
                        icon=$Sketch
                        validation=$Sketch_validation
                    ;;
                    *Miro*)
                        icon=$Miro
                        validation=$Miro_validation
                    ;;
                    *Microsoft_Skype_for_Busines* | *Microsoft\ Skype\ for\ Busines* | *Skype\ for\ Busines*)
                        icon=$Microsoft_Skype_for_Business
                        validation=$Microsoft_Skype_for_Business_validation
                    ;;
                    *Keka*)
                        icon=$Keka
                        validation=$Keka_validation
                    ;;
                    *ImageOptim*)
                        icon=$ImageOptim
                        validation=$ImageOptim_validation
                    ;;
                    *Filezilla*)
                        icon=$Filezilla
                        validation=$Filezilla_validation
                    ;;
                    *DropBox*)
                        icon=$DropBox
                        validation=$DropBox_validation
                    ;;
                    *Figma*)
                        icon=$Figma
                        validation=$Figma_validation
                    ;;
                    *EasyFind*)
                        icon=$EasyFind
                        validation=$EasyFind_validation
                    ;;
                    *DisplayLink_Manager* | *DisplayLink\ Manager*)
                        icon=$DisplayLink_Manager
                        validation=$DisplayLink_Manager_validation
                    ;;
                    *Cyberduck*)
                        icon=$Cyberduck
                        validation=$Cyberduck_validation
                    ;;
                    *Blender*)
                        icon=$Blender
                        validation=$Blender_validation
                    ;;
                    *Balsamiq_Wireframes* | *Balsamiq\ Wireframes*)
                        icon=$Balsamiq_Wireframes
                        validation=$Balsamiq_Wireframes_validation
                    ;;
                    *AppCleaner*)
                        icon=$AppCleaner
                        validation=$AppCleaner_validation
                    ;;
                    *Adobe_Creative_Cloud_Desktop* | *Adobe\ Creative\ Cloud\ Desktop*)
                        icon=$Adobe_Creative_Cloud_Desktop
                        validation=$Adobe_Creative_Cloud_Desktop_validation
                    ;;
                    *1Password_8* | *1Password\ 8* | *1Password*)
                        icon=$Password
                        validation=$Password_validation
                    ;;
                    *Adobe_Acrobar_Reader* | *Adobe\ Acrobar\ Reader*)
                        icon=$Adobe_Acrobar_Reader
                        validation=$Adobe_Acrobar_Reader_validation
                    ;;
                    *Anydesk*)
                        icon=$Anydesk
                        validation=$Anydesk_validation
                    ;;
                    *Audacity*)
                        icon=$Audacity
                        validation=$Audacity_validation
                    ;;
                    *balenaEtcher* | *balena\ Etcher*)
                        icon=$balenaEtcher
                        validation=$balenaEtcher_validation
                    ;;
                    *Clipy*)
                        icon=$Clipy
                        validation=$Clipy_validation
                    ;;
                    *Drawio* | *Draw.io*)
                        icon=$Drawio
                        validation=$Drawio_validation
                    ;;
                    *Keeping_you_Awake* | *Keeping\ you\ Awake*)
                        icon=$Keeping_you_Awake
                        validation=$Keeping_you_Awake_validation
                    ;;
                    *Monitor_Control* | *Monitor\ Control*)
                        icon=$Monitor_Control
                        validation=$Monitor_Control_validation
                    ;;
                    *OmniGraffle_7* | *OmniGraffle\ 7* | *Omni\ Graffle\ 7* | *Omni\ Graffle*)
                        icon=$OmniGraffle_7
                        validation=$OmniGraffle_7_validation
                    ;;
                    *Rectangle*)
                        icon=$Rectangle
                        validation=$Rectangle_validation
                    ;;
                    *Sourcetree*)
                        icon=$Sourcetree
                        validation=$Sourcetree_validation
                    ;;
                    *Zulip*)
                        icon=$Zulip
                        validation=$Zulip_validation
                    ;;
                    *Go_to_Meeting* | *Go\ to\ Meeting*)
                        icon=$Go_to_Meeting
                        validation=$Go_to_Meeting_validation
                    ;;
                    *GIMP*)
                        icon=$GIMP
                        validation=$GIMP_validation
                    ;;
                    *Apache_Directory_Studio* | *Apache\ Directory\ Studio*)
                        icon=$Apache_Directory_Studio
                        validation=$Apache_Directory_Studio_validation
                    ;;
                    *Azure_Data_Studio* | *Azure\ Data\ Studio*)
                        icon=$Azure_Data_Studio
                        validation=$Azure_Data_Studio_validation
                    ;;
                    *Docker*)
                        icon=$Docker
                        validation=$Docker_validation
                    ;;
                    *Meld*)
                        icon=$Meld
                        validation=$Meld_validation
                    ;;
                    *PyCharm*)
                        icon=$PyCharm
                        validation=$PyCharm_validation
                    ;;
                    *SquidMan* | *Squid\ Man*)
                        icon=$SquidMan
                        validation=$SquidMan_validation
                    ;;
                    *TNEFs_Enough* | *TNEFs\ Enough*)
                        icon=$TNEFs_Enough
                        validation=$TNEFs_Enough_validation
                    ;;
                    *Wireshark*)
                        icon=$Wireshark
                        validation=$Wireshark_validation
                    ;;
                    *Jabra_Direct* | *Jabra\ Direct*)
                        icon=$Jabra_Direct
                        validation=$Jabra_Direct_validation
                    ;;
                    *SimpleMind_Pro* | *SimpleMind\ Pro* | *Simple\ Mind\ Pro*)
                        icon=$SimpleMind_Pro
                        validation=$SimpleMind_Pro_validation
                    ;;
                    *Tunnelblick*)
                        icon=$Tunnelblick
                        validation=$Tunnelblick_validation
                    ;;
                    *UTM*)
                        icon=$UTM
                        validation=$UTM_validation
                    ;;
                    *Bitwarden*)
                        icon=$Bitwarden
                        validation=$Bitwarden_validation
                    ;;
                    *Safari*)
                        icon=$Safari
                        validation=$Safari_validation
                    ;;
                    *Brave*)
                        icon=$Brave
                        validation=$Brave_validation
                    ;;
                    
                    *)
                        icon="$placeholder_icon"
                        validation="$placeholder_validation"
                    ;;
                esac
                
                policyJSON+='
        {
            "listitem": "'${PolicyName}'",
            "icon": "'$icon'",
            "progresstext": "Updating '${PolicyName}'",
            "trigger_list": [
                {
                    "trigger": "'${IDs[i]}'",
                    "validation": "'$validation'"
                }
            ]
        }'
                
                if ((i != ${#IDs[@]} - 1)); then
                    policyJSON+=','
                fi
            done
    
    # Step for "Update Inventory"
    policyJSON+='
        ,
        {
            "listitem": "Update Inventory",
            "icon": "ff2147a6c09f5ef73d1c4406d00346811a9c64c0b6b7f36eb52fcb44943d26f9",
            "progresstext": "Updating Inventory",
            "trigger_list": [
                {
                    "trigger": "recon",
                    "validation": "None"
                }
            ]
        }
    ]

}'
}

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
        updateScriptLog "Patch Helper DIALOG: RUNNING: $jamfBinary policy -id $trigger"
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
        updateScriptLog "The '$process' process isn't running."
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
    updateScriptLog "Revoke API Token"
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
        updateScriptLog "QUIT SCRIPT: Removing default dialog file …"
        rm /var/tmp/dialog.log
    fi

    # Remove tmp files
    if [[ -e ${xsltFile} ]]; then
        updateScriptLog "QUIT SCRIPT: Removing ${xsltFile} …"
        rm "${xsltFile}"
    fi
    
    if [[ -e ${xmlFile} ]]; then
        updateScriptLog "QUIT SCRIPT: Removing ${xmlFile} …"
        rm "${xmlFile}"
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
# Function create LaunchDaemon 
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #    
    
function createLaunchDaemon() {

/bin/cat <<EOC > /Library/LaunchDaemons/it.next.UpdateEnforce.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>it.next.UpdateEnforce</string>
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
    <integer>$StartInterval</integer>
    <key>UserName</key>
    <string>root</string>
</dict>
</plist>
EOC
    
}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Function start the LaunchDaemon 
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
function StartLaunchDaemon() {
    # set ownership on LastWarningDaemon launch daemon
    updateScriptLog "Patch Helper DIALOG: Change permissions for the Daemon…"
    /usr/sbin/chown root:wheel /Library/LaunchDaemons/it.next.UpdateEnforce.plist
    /bin/chmod 644 /Library/LaunchDaemons/it.next.UpdateEnforce.plist
    
    #load launchd
    updateScriptLog "Patch Helper DIALOG: Load the Daemon …"
    launchctl load /Library/LaunchDaemons/it.next.UpdateEnforce.plist
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

    if [[ -z "${welcomeResults}" ]]; then
        PromtUser="2"
    else
        PromtUser="0"
    fi

    case "${PromtUser}" in

        0)  # Process exit code 0 scenario here
            echo "Exit 0"
                        
            updateScriptLog "PROMT USER DIALOG: ${loggedInUser} entered information and clicked Continue"

            ###
            # Extract the various values from the welcomeResults JSON
            ###

            Updates=$(get_json_value_UserInformation "$welcomeResults" "selectedValue")
            
            ###
            # Select `policyJSON` based on selected Configuration
            ###

            UpdateJSONConfiguration
            # Output `recon` options to log
            updateScriptLog "PROMT USER DIALOG: reconOptions: ${reconOptions}"

            ###
            # Display "Patch Helper" dialog (and capture Process ID)
            ###

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
                ###
                # First check if a displacement is already present.
                ###
                CheckDeferral

                updateScriptLog "PROMT USER DIALOG: ${loggedInUser} clicked Quit at PROMT USER DIALOG"
                completionActionOption="Quit"
                quitScript "1"
            else
            updateScriptLog "PROMT USER DIALOG: ${loggedInUser} clicked Command Q at PROMT USER DIALOG"
            
            ###
            # Extract the various values from the welcomeResults JSON
            ###
            
            Updates=$(get_json_value_UserInformation "$welcomeResults" "selectedValue")
            
            ###
            # Select `policyJSON` based on selected Configuration
            ###
            
            UpdateJSONConfiguration
            # Output `recon` options to log
            updateScriptLog "PROMT USER DIALOG: reconOptions: ${reconOptions}"
            
            ###
            # Display "Patch Helper" dialog (and capture Process ID)
            ###
            
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
    UpdateJSONConfiguration
    
    
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
        updateScriptLog "\n\n# # #\n# Patch Helper DIALOG: policyJSON > listitem: ${listitem}\n# # #\n"
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
