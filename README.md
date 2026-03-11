# Microsoft Sentinel Incident Response Lab: Impossible Travel Detection

> Note: All user identifiers, domains, and IP information have been anonymized before publication.

## Overview
This lab demonstrates how Microsoft Sentinel can detect and investigate suspicious authentication activity using Azure Active Directory logs.
## Lab Environment
| Component            | Technology                              |
| -------------------- | --------------------------------------- |
| SIEM                 | Microsoft Sentinel                      |
| Log Source           | Azure AD Sign-in Logs                   |
| Log Table            | `SigninLogs`                            |
| Query Language       | Kusto Query Language (KQL)              |
| Investigation Method | NIST 800-61 Incident Response Lifecycle |

## Detection Rule

The detection rule analyzes Azure authentication logs and identifies accounts logging in from multiple geographic locations within a defined time window.
## Detection Query

```kql
let TimePeriodThreshold = timespan(7d);
let NumberOfDifferentLocationsAllowed = 2;

SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by UserPrincipalName, UserId,
    City = tostring(parse_json(LocationDetails).city),
    State = tostring(parse_json(LocationDetails).state),
    Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, UserId
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed
```
Detection Logic

This query:

1. Reviews 7 days of authentication logs.
2. Extracts geographic location data from the LocationDetails field.
3. Counts unique login locations per user.
4. Triggers when a user logs in from more than two locations.

This behavior may indicate credential compromise or suspicious authentication activity.

## MITRE ATT&CK Mapping
| Technique | Name                 |
| --------- | -------------------- |
| T1078     | Valid Accounts       |
| T1098     | Account Manipulation |

## Incident Investigation

Once the analytics rule triggered, Microsoft Sentinel generated an incident titled:

Potential Impossible Travel

The incident contained several user entities associated with the alert.

Each account was investigated individually using authentication logs.
```kql
let TimePeriodThreshold = timespan(7d);
let InvestigatedUser = "user_account@tenant-domain.com";

SigninLogs
| where UserPrincipalName == InvestigatedUser
| where TimeGenerated > ago(TimePeriodThreshold)
| project TimeGenerated, UserPrincipalName, IPAddress,
         City = tostring(parse_json(LocationDetails).city),
         State = tostring(parse_json(LocationDetails).state),
         Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc
```
This query provides a timeline of authentication activity for the investigated user.

## Observed Login Activity
| Time         | City              | State | Country |
| ------------ | ----------------- | ----- | ------- |
| 5:28 PM      | Atlanta           | GA    | US      |
| 1:41 PM      | Dallas–Fort Worth | TX    | US      |
| 12:38 PM     | San Jose          | CA    | US      |
| 12:37 PM     | Atlanta           | GA    | US      |
| 11:39 AM     | Atlanta           | GA    | US      |
| Previous Day | Columbus          | GA    | US      |


## Investigation Findings

Although the detection rule identified multiple geographic locations, further analysis determined that the activity was legitimate.

Key findings:

  1. Authentication occurred from both home and workplace networks

  2. All logins originated from the United States

  3. Some login locations correspond to the Microsoft cloud authentication infrastructure

Cloud authentication endpoints can cause login events to appear from cities such as San Jose or Dallas, even when the user has not physically traveled.

Because the login behavior matched normal user activity and no indicators of compromise were identified, the alert was deemed benign.

## Containment and Response

If the activity had been malicious, standard containment actions would include:

  1. Temporarily disabling the affected account in Microsoft Entra ID

  2. Contacting the user or their manager

  3. Investigating additional activity associated with the account

  4. Reviewing Azure resource activity logs

Example pivot query:
```kql
AzureActivity
| where tostring(parse_json(Claims)["http://schemas.microsoft.com/identity/claims/objectidentifier"]) == "user-object-id"
```
In this scenario, no containment actions were required because the authentication activity was legitimate.

## Post-Incident Improvements

Although the activity was benign, organizations can reduce similar alerts by implementing additional security controls:

  1. Conditional Access Policies

  2. Multi-Factor Authentication (MFA)

  3. Geographic login restrictions (geo-fencing)

  4. Risk-based sign-in policies

These controls help prevent credential compromise and unauthorized access attempts.

## Incident Closure

After completing the investigation and confirming that the authentication activity represented legitimate user behavior, the incident was closed in Microsoft Sentinel.

Final Classification

Benign Positive

No malicious activity was identified, and no remediation actions were required.

## Skills Demonstrated

This lab demonstrates practical Security Operations Center (SOC) analyst skills, including:

  1. Microsoft Sentinel detection engineering

  2. KQL log analysis

  3. Azure authentication investigation

  4. MITRE ATT&CK mapping

  5. Cloud security monitoring

  6. Incident response using NIST 800-61


## Key Takeaways

This lab demonstrates how security analysts detect and investigate suspicious authentication behavior in cloud environments.

Key lessons learned include:

  • Impossible travel alerts require investigation – Multiple geographic login locations do not always indicate malicious activity. Cloud authentication infrastructure and legitimate user travel can trigger false positives.

  • KQL is critical for security investigations – Analysts must use Kusto Query Language to review authentication logs, analyze login timelines, and determine whether suspicious activity represents legitimate behavior or a compromise.

  • Context matters during incident response – Investigations must consider factors such as user behavior, network locations, and authentication patterns before determining whether an incident is malicious.

  • Cloud authentication logs can appear misleading – Login locations may reflect Microsoft cloud authentication endpoints rather than the user's physical location.

  • Detection rules should balance sensitivity and noise – While impossible travel rules are useful for detecting potential credential compromise, tuning detection thresholds and implementing conditional access policies can reduce false positives.

  • Incident response follows a structured process – Using the NIST 800-61 Incident Response Lifecycle ensures that alerts are investigated consistently and documented properly.


  Detection Engineering Notes

The detection rule used in this lab identifies potential impossible travel scenarios by analyzing Azure Active Directory authentication logs stored in the SigninLogs table. The rule counts the number of geographic locations associated with a user account within a seven-day time period and triggers an alert when the number of locations exceeds the configured threshold.

While this approach successfully detects suspicious authentication behavior, it also highlights several important considerations for detection engineering.

Detection Strengths

• Early detection of credential abuse
Monitoring authentication logs allows security teams to detect potential account compromise quickly when login behavior appears abnormal.

• Simple and efficient query logic
The rule uses straightforward KQL logic to identify users logging in from multiple geographic locations without requiring complex calculations.

• Works well in cloud environments
Azure authentication logs provide rich metadata such as IP addresses and location information, making it possible to identify suspicious login activity.

## Detection Limitations

• False positives caused by cloud infrastructure
Authentication events may appear to originate from different cities due to Microsoft cloud authentication endpoints rather than actual user movement.

• VPN usage
Users connecting through VPN services may appear to authenticate from different geographic regions.

• Legitimate travel
Users who travel frequently may trigger impossible travel alerts even when their activity is legitimate.

## Potential Improvements

In production environments, security teams often improve impossible travel detection by implementing additional context and controls:

Risk-based sign-in detection
Microsoft Entra ID Identity Protection can automatically detect risky sign-ins based on behavioral analytics.

Conditional Access policies
Organizations can require additional authentication factors when users log in from unfamiliar locations.

Geo-fencing policies
Access can be restricted to specific geographic regions to reduce unauthorized authentication attempts.

Travel velocity calculations
More advanced detection rules calculate the physical distance between login locations and determine whether travel between those locations would be physically possible within the time window.

## Example Advanced Detection Concept

A more advanced impossible travel detection might compare login timestamps and geographic distance between login locations to determine whether the travel speed exceeds what would be physically possible.

This type of detection reduces false positives and improves accuracy when identifying compromised accounts.
