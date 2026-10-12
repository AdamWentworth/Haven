# Device reporting expectations

Choose each enrolled device's reporting expectation on the Devices page:

- **Always on** keeps the existing medium-severity overdue alert when the hub has received no authenticated report for more than 35 minutes.
- **Used intermittently** shows “Not currently reporting” after that same freshness allowance. After more than seven days without contact, a low-severity check-in reminder asks you to check the agent when you next use the device. Low-severity reminders do not generate push interruptions.

Silence does not establish sleep, shutdown, loss of connectivity, or an agent failure. HAVEN reports the last authenticated contact and observation time without guessing the cause. A fresh report clears the absence or reminder automatically.

An intermittent expectation does not accept a security risk, dismiss a finding, revoke an identity, or change collection frequency. Previous findings remain visible as last observed evidence. Older reports are evaluated at their collection time so merely waiting does not manufacture newly aged posture findings. Expiring owner reviews and service expectations continue to use the hub's current clock.

Coverage summaries count only fresh reports as currently reporting or currently protected. Expected absence is neutral; missing evidence is never presented as verified health. The selected device view labels older posture and connection details with their observation time.

## Policy and compatibility

The hub owns both thresholds and exposes its derived reporting status. The dashboard never derives thresholds independently. The owner setting is one fixed enum per enrolled device, stored in SQLite and changed through the authenticated, origin-checked, CSRF-protected API. The policy change and bounded audit entry commit together. Endpoint observations cannot change it, and there are no new collection privileges or observation fields.

The additive migration defaults existing devices to always on, preserving prior behavior until the owner chooses otherwise. A complete state backup preserves these decisions. An older hub can still read the additive database schema, but uses its original overdue policy; rolling back the application therefore also restores the previous alert behavior.
