#!/bin/bash

#######################################################################
# Script          : Patch Helper - LaunchDaemon Cleanup
# Purpose         : Remove the Patch Helper LaunchDaemon
#                  and unload it from launchd
#######################################################################

export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/local/jamf/bin

#######################################################################
# Configuration
#######################################################################

ManagedPreferences="/Library/Managed Preferences/it.next.PatchHelper.plist"

LaunchDaemonLabelOverride="${4:it.next.PatchHelper}"

#######################################################################
# Logging
#######################################################################

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
}

#######################################################################
# Root check
#######################################################################

if [[ $(id -u) -ne 0 ]]; then
    log "ERROR: Script must be executed as root."
    exit 1
fi

#######################################################################
# Determine LaunchDaemon label
#######################################################################

if [[ -n "$LaunchDaemonLabelOverride" ]]; then

    LaunchDaemonLabel="$LaunchDaemonLabelOverride"

    log "Using LaunchDaemon label from Jamf parameter 4:"
    log "LaunchDaemonLabel = $LaunchDaemonLabel"

else

    if [[ ! -f "$ManagedPreferences" ]]; then
        log "ERROR: Managed Preferences not found:"
        log "$ManagedPreferences"
        log "Unable to determine LaunchDaemon label."
        exit 1
    fi

    LaunchDaemonLabel=$(
        /usr/libexec/PlistBuddy \
            -c "Print :Daemon_and_Deferral_Settings:LaunchDaemonLabel" \
            "$ManagedPreferences" \
            2>/dev/null
    )

    if [[ -z "$LaunchDaemonLabel" ]]; then
        log "ERROR: LaunchDaemonLabel could not be read from:"
        log "$ManagedPreferences"
        exit 1
    fi

    log "LaunchDaemon label read from Managed Preferences:"
    log "LaunchDaemonLabel = $LaunchDaemonLabel"

fi

#######################################################################
# LaunchDaemon variables
#######################################################################

LaunchDaemonPlist="/Library/LaunchDaemons/${LaunchDaemonLabel}.plist"
LaunchDaemonService="system/${LaunchDaemonLabel}"

LaunchDaemonPlistExists="false"
LaunchDaemonLoaded="false"

#######################################################################
# Determine current state
#######################################################################

refreshLaunchDaemonState() {

    LaunchDaemonPlistExists="false"
    LaunchDaemonLoaded="false"

    if [[ -f "$LaunchDaemonPlist" ]]; then
        LaunchDaemonPlistExists="true"
    fi

    if /bin/launchctl print "$LaunchDaemonService" >/dev/null 2>&1; then
        LaunchDaemonLoaded="true"
    fi
}

#######################################################################
# Initial state
#######################################################################

refreshLaunchDaemonState

log "Initial LaunchDaemon state:"
log "plist  = $LaunchDaemonPlistExists"
log "loaded = $LaunchDaemonLoaded"
log "path   = $LaunchDaemonPlist"
log "service= $LaunchDaemonService"

#######################################################################
# Nothing to clean
#######################################################################

if [[ "$LaunchDaemonPlistExists" == "false" && \
      "$LaunchDaemonLoaded" == "false" ]]; then

    log "LaunchDaemon is already completely removed."
    exit 0

fi

#######################################################################
# Step 1 - Remove plist
#######################################################################

if [[ "$LaunchDaemonPlistExists" == "true" ]]; then

    log "Removing LaunchDaemon plist:"
    log "$LaunchDaemonPlist"

    if ! /bin/rm -f "$LaunchDaemonPlist"; then
        log "ERROR: Could not remove LaunchDaemon plist."
        exit 1
    fi

    ###################################################################
    # Verify plist removal
    ###################################################################

    if [[ -e "$LaunchDaemonPlist" ]]; then
        log "ERROR: LaunchDaemon plist still exists after removal attempt."
        exit 1
    fi

    log "LaunchDaemon plist removed successfully."

else

    log "LaunchDaemon plist does not exist."
    log "No plist removal required."

fi

#######################################################################
# Step 2 - Remove service from launchd
#######################################################################

refreshLaunchDaemonState

if [[ "$LaunchDaemonLoaded" == "true" ]]; then

    log "LaunchDaemon is still loaded."
    log "Running launchctl bootout:"
    log "/bin/launchctl bootout $LaunchDaemonService"

    bootoutOutput=$(
        /bin/launchctl bootout "$LaunchDaemonService" 2>&1
    )

    bootoutResult=$?

    if [[ $bootoutResult -ne 0 ]]; then
        log "ERROR: launchctl bootout failed."
        log "Exit code: $bootoutResult"

        if [[ -n "$bootoutOutput" ]]; then
            log "launchctl output:"
            log "$bootoutOutput"
        fi

        exit 1
    fi

    log "launchctl bootout completed successfully."

else

    log "LaunchDaemon is not loaded."
    log "No bootout required."

fi

#######################################################################
# Final verification
#######################################################################

sleep 1

refreshLaunchDaemonState

log "Final LaunchDaemon state:"
log "plist  = $LaunchDaemonPlistExists"
log "loaded = $LaunchDaemonLoaded"

if [[ "$LaunchDaemonPlistExists" == "true" || \
      "$LaunchDaemonLoaded" == "true" ]]; then

    log "ERROR: LaunchDaemon cleanup was not completely successful."
    exit 1

fi

#######################################################################
# Finished
#######################################################################

log "LaunchDaemon cleanup completed successfully."
exit 0