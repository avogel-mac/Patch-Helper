![](https://github.com/avogel-mac/Patch-Helper/blob/main/Pictures/255599822-d9cfb58e-2c11-466d-8549-c5824b608f7a.PNG?raw=true)


⚠️ Important Release Notes – Version 1.0.0 (June 3, 2025)

Please carefully review the following changes before deploying this version of the script in Jamf Pro:

📌 Configuration Management Update

Script Management via Configuration Profile:The script is now managed through a configuration profile.

Pre-filled JSON:

Use PatchHelper_Settings_with_pre-filled_text.json to leverage pre-filled text entries.

Select desired text values from dropdown menus; edits can be made as necessary.

Manual JSON:

Alternatively, use PatchHelper_Settings.json if you prefer to set all text entries manually.

🔑 API Token Management

API Tokens via API Roles and Clients:API tokens must now be created using Jamf Pro’s "API Roles and Clients" feature.

Dedicated Jamf Pro user accounts for API access are no longer required.

🎨 Icons and Validation Checks

Centralized Icons:

Icons and validation checks are no longer defined within the script.

These are now provided via the profile file named icon_service.json.

Improved Reusability:

Centralizing icons simplifies updates and allows reuse across multiple scripts.

## Patch Helper
A script that serves to display to the user all available updates for the affected device in a dialogue.

## What does it do?
The script consolidates the various update notifications and generates a single window for the user that:

_- Informs about the number of updates available_

_- Lists which applications will be updated_

_- Provides the count of available postponements_

_- Specifies how frequently the dialogue restarts._

![](https://github.com/avogel-mac/Patch-Helper/blob/main/Pictures/256270676-d6995872-61c8-4079-9f09-cbc0580d4203.png?raw=true)
![](https://github.com/avogel-mac/Patch-Helper/blob/main/Pictures/256270727-dc265a33-b074-4949-8186-cdcc0831cbd2.png?raw=true)



The user will be informed about which applications are currently being updated and also about the results.
![](https://github.com/avogel-mac/Patch-Helper/blob/main/Pictures/256270766-e8d5cd47-e0ca-43cc-bdb6-99eb6ec2be2f.png?raw=true)




## Preparing
Download the latest Version of the Script.

Enable Patch Management in Jamf Pro. This will subsequently serve for:

_1. A graphical representation in Jamf Pro_

_2. Creating dynamic groups for the policies_

For a step-by-step guide, please refer to the Wiki.


## Configuration

For the configuration of the policy, please refer to the following guide.

## It's not working!
Sorry about that. If you're willing and able to help test, please report.
