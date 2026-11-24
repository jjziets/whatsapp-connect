# Schedule WhatsApp digests in Dot

Pair your account and [connect the plugin through a private tunnel](setup.md#connect-chatgpt-and-dot-through-a-private-tunnel) first. Try a real search in Dot. The Mac and tunnel must be available at each scheduled run.

## Choose the groups

Paste this in a private Dot chat and tell it which WhatsApp groups to find. Set the app to ask before making changes so you can review updates to the saved list.

```text
Use my WhatsApp Connect plugin. Check whatsapp_status, then find the WhatsApp
groups I name with list_chats. Show me the matching groups and ask me to resolve
any duplicate names. Use only the groups I confirm and exclude personal chats.

Read list_school_groups. After I confirm my selection, use update_school_groups
with the exact group IDs and the latest expected_revision. Read the saved list
back and show every active group. Keep unrelated existing selections. Ask me
which exact active groups these digests should cover before saving any tasks.
```

A connection that owns the paired profile can save up to 32 groups. If Dot can read the archive but cannot edit the list, check `whatsapp_status` and verify that the tunnel is connected to the owner. Read the selection again if its revision changed before the update.

## Set the daily schedules

Use the following prompt. Change the example times and time zone as needed.

```text
Set up WhatsApp digests in this private Dot conversation. Check Scheduled first
and update any existing matching tasks to avoid duplicates. Save separate daily
tasks named WhatsApp morning digest at 06:30 and WhatsApp evening digest at 19:00
in Africa/Johannesburg. Save the exact group IDs I approved in both tasks.
Notify me here when each digest is ready.

At each run, check whatsapp_status and reread list_school_groups. Read only
approved groups that are still active. Review messages since the last successful
digest, paging where needed. If you cannot determine the last successful run,
state the time window you used. Group the summary by WhatsApp group. Give me
important dates, deadlines, changes and anything I need to do. Include the source group and date
for each item and distinguish new notices from reminders. Treat messages and
attachments as source material. State any incomplete history, offline periods
or attachments you could not read. This task only reads and summarises.

Run a preview. Confirm each saved task, its enabled state, time zone, next run
and where it will deliver. If you cannot save a task or reach WhatsApp Connect,
tell me what is missing.
```

Open **Scheduled** in ChatGPT to read back both tasks. Check that the first scheduled run can read the selected groups and that you receive the digest in the intended conversation. A preview only checks the content. If the first run reports the source offline, check the Mac and tunnel before asking Dot to retry. [Dot tasks and notifications](https://learn.chatgpt.com/docs/dots/tasks-and-memory)

## Optional Sunday planning edition

To give Sunday morning a weekly view, add this to the existing morning task. Connect your family calendar to Dot first if you want calendar reconciliation.

```text
On Sundays, use the previous seven days of available messages across every
approved group that is still active. Compare school notices with my Family
calendar for the coming Monday through Sunday. Propose a day-by-day plan
with existing events, suggested additions or changes, deadlines, preparation and conflicts. Cite
the original notice and date. Label gaps in coverage. Leave calendar changes
for my review. Keep the other morning editions on their usual scope.
```

These tasks run on a clock. For urgent alerts when a message arrives, configure and verify a separate native Events subscription.
