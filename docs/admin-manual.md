# UCOSA-NA Website — Administrator Manual

**Version:** 2026 | **Site:** ucosa-na.org | **Support:** admin@ucosa-na.org

---

## Table of Contents

1. [Overview](#1-overview)
2. [Roles and Permissions](#2-roles-and-permissions)
3. [Accessing the Admin Panel](#3-accessing-the-admin-panel)
4. [Member Management](#4-member-management)
5. [Annual Dues](#5-annual-dues)
6. [Endowment Fund](#6-endowment-fund)
7. [Broadcasts (SMS / Email / Invitation)](#7-broadcasts)
8. [Meeting Notes](#8-meeting-notes)
9. [Welfare Directory](#9-welfare-directory)
10. [Audit Log](#10-audit-log)
11. [Log Viewer](#11-log-viewer)
12. [Site Maintenance](#12-site-maintenance)
13. [Security](#13-security)
14. [Automated Scheduler](#14-automated-scheduler)

---

## 1. Overview

The UCOSA-NA web platform provides:

- A **public-facing website** (home page, about, constitution, member gallery, executive pages, events/gallery).
- A **Members Portal** (`/members.html`) where logged-in members view their financial records, meeting notes, and update their contact info.
- An **Admin Panel** (`/admin.html`) where privileged staff manage members, finances, communications, and site settings.

---

## 2. Roles and Permissions

| Role | Label | Access |
|---|---|---|
| `admin` | Admin | Full access to all sections. Only role that can create other admins, delete members, access audit log, and manage site maintenance. |
| `fin-role` | Fin-Sec | Annual Dues, Endowment Fund, Broadcasts. |
| `security-role` | Secretary | Create/manage members, bulk import, meeting notes, log viewer, broadcasts. |
| `pro-role` | PRO | Broadcasts only. |
| `welfare` | Welfare | Welfare member directory, broadcasts. |
| `member` | Member | Members Portal only (no admin panel access). |

> **Note:** User ID 1 (root admin) is excluded from all member lists, dues, and endowment views.

---

## 3. Accessing the Admin Panel

1. Navigate to `https://ucosa-na.org`.
2. Click **Sign In** in the top navigation bar.
3. Enter your admin email and password.
4. You will be redirected to `/admin.html` automatically if your role is `admin`, `fin-role`, `security-role`, `pro-role`, or `welfare`.

**Session duration:** 8 hours. After expiry you will be logged out automatically.

### First Login
All new accounts are issued a temporary password. On first login you will be redirected to `/change-password.html` and must set a permanent password before accessing any features.

**Password requirements:**
- Minimum 8 characters
- At least one uppercase letter
- At least one special character (e.g. `!@#$%^&*`)

---

## 4. Member Management

> Accessible by: **Admin**, **Secretary**

### 4.1 Viewing All Members

The **All Members** table displays every registered user (except ID 1) in alphabetical order, showing:
- First Name, Last Name, Email, Phone, Address
- Year Joined, Graduation Year
- Role, Last Login, Status (Active / Suspended / Locked), Must Change Password flag
- Action buttons: Edit, Reset PW, Suspend/Reinstate, Lock/Unlock, Remove

Use the **Search** box to filter by name, email, or phone in real time.

### 4.2 Creating a Member

1. Scroll to the **Create New Member** section.
2. Fill in: First Name, Last Name, Email, Phone (required), Address, Year Joined, Graduation Year, Role.
3. Click **Create Member**.
4. The system generates a temporary password and sends a welcome email to the member with login instructions.
5. The temporary password is also displayed on screen — note it down as a backup.

> Only admins can assign the `admin` role. All other privileged roles can be assigned by admin or secretary.

### 4.3 Editing a Member

Click **Edit** on any member row. A modal opens allowing updates to:
- First Name, Last Name, Email, Phone, Address, Year Joined, Graduation Year.

Click **Save Changes** when done.

### 4.4 Resetting a Password

Click **Reset PW** on any member row. The system will:
- Generate a new temporary password.
- Email it to the member.
- Display the new password on screen.
- Flag the account as `must_change_password = true` so the member must set a new password on next login.

### 4.5 Suspending / Reinstating a Member

- **Suspend:** Click the red **Suspend** button. The member cannot log in while suspended.
- **Reinstate:** Click the green **Reinstate** button to restore access.

### 4.6 Locking / Unlocking a Member

- **Lock:** Prevents login. Use for security purposes (e.g. suspected account compromise).
- **Unlock:** Restores login access.

> Only admins can lock/unlock or suspend/reinstate other admin accounts.

### 4.7 Changing a Member's Role

In the **Role** column of the All Members table, use the dropdown to select a new role. The change takes effect immediately on the next login.

### 4.8 Removing a Member

Click **Remove** (red button). A confirmation prompt appears. This permanently deletes the member and all associated records. **This action cannot be undone.**

### 4.9 Bulk Import (CSV)

1. Scroll to **Bulk Import**.
2. Download the CSV template if needed.
3. Prepare a CSV file with columns: `first_name, last_name, email, phone, address, year_joined, graduation_year, role`.
4. Click **Choose File**, select your CSV, then click **Preview** to review the parsed data.
5. Click **Import Members** to create accounts for all valid rows.
6. Results show how many were created, skipped (already exist), or failed.

### 4.10 Downloading the Member List (CSV)

Click **Download CSV** at the top of the All Members section to export all members as a spreadsheet.

---

## 5. Annual Dues

> Accessible by: **Admin**, **Fin-Sec**

Annual dues are due on **June 4th** each year. The system seeds dues records automatically on January 1st for all members.

### 5.1 Adding a Dues Record

1. Select a **Member** from the dropdown.
2. Enter the **Year**.
3. Enter the **Amount** (default $100.00).
4. Optionally set **Paid Date**, **Payment Method**, **Notes**.
5. Set **Status**: Unpaid (default), Partial, or Paid.
6. Click **Add Dues Record**.

### 5.2 Editing a Dues Record

Click **Edit** on any row in the dues table. The form populates with the existing data. Make changes and click **Update Record**. Click **Cancel Edit** to discard.

### 5.3 Deleting a Dues Record

Click **Delete** on any row. A confirmation prompt appears. Deletion is permanent.

### 5.4 Filtering Dues

Use the filters above the dues table to narrow results by:
- **Year** — enter a specific year
- **Status** — All, Unpaid, Partial, Paid
- **Search** — search by member name

Members with no dues records appear with status **No record**.

### 5.5 Sending a Dues Reminder (SMS)

Click **Remind** (teal button) on any dues row. An SMS is sent to the member's phone number containing:
- Their dues amount and current status
- Zelle payment instructions: `ucosa.northamerica@gmail.com`
- A note to ignore the message if already paid

> The member must have a phone number on file. If not, an error is shown.

### 5.6 Automated Reminders

The scheduler sends reminders automatically:
- **May 4th at 9:00 AM ET** — 30-day advance reminder (email + SMS) to all unpaid/partial members.
- **June 4th at 9:00 AM ET** — Due-date reminder (email + SMS) to all unpaid/partial members.

---

## 6. Endowment Fund

> Accessible by: **Admin**, **Fin-Sec**

### 6.1 Adding an Endowment Record

1. Select a **Member** from the dropdown.
2. Enter **Amount**, **Year**, **Status** (Paid / Partial / Unpaid), **Contribution Date**, **Payment Method**, **Notes**.
3. Click **Add Endowment Record**.

### 6.2 Editing an Endowment Record

Click **Edit** on any row. Update fields and click **Update Record**.

### 6.3 Deleting an Endowment Record

Click **Delete** on any row. Permanent — cannot be undone.

### 6.4 Filtering

Filter by Year, Status, and member name search.

### 6.5 Sending an Endowment Reminder

Click **Remind** on any row to send an SMS and email reminder to the member with the Zelle payment details.

---

## 7. Broadcasts

> SMS/Email accessible by: **Admin**, **Fin-Sec**, **Secretary**, **PRO**, **Welfare**
> Invitations accessible by same roles.

### 7.1 SMS Broadcast

Send a bulk SMS to all members who have a phone number on file.

1. Type your message in the text area.
2. Click **Send SMS Broadcast**.
3. A summary shows how many were sent, failed, or skipped (no phone).

### 7.2 Email Broadcast

Send a bulk email to all members.

1. Enter the **Subject** and **Message body**.
2. Click **Send Email Broadcast**.

### 7.3 Invitation Broadcast

Send membership invitation emails to prospective members.

1. Enter one or more email addresses (comma-separated).
2. Click **Send Invitations**.
3. Each recipient receives a styled invitation email with a link to the website.

---

## 8. Meeting Notes

> Accessible by: **Admin**, **Secretary**

### 8.1 Uploading Meeting Notes

1. Enter the **Meeting Title** and **Meeting Date**.
2. Click **Choose File** and select a PDF document (max 20 MB).
3. Click **Upload**.
4. The file is stored securely and becomes visible to all logged-in members.

### 8.2 Managing Meeting Notes

The notes list shows all uploaded documents with title, date, and upload date. Admins and secretaries can **delete** any note. Members can only view and download.

---

## 9. Welfare Directory

> Accessible by: **Admin**, **Welfare**

The welfare directory shows a simplified member list with name, email, and phone for welfare-related outreach. It can be exported as a CSV using the **Download CSV** button.

---

## 10. Audit Log

> Accessible by: **Admin** only

The audit log records every significant action taken in the system including:
- Member created, updated, deleted
- Dues and endowment records created, updated, deleted
- Login successes and failures
- Password changes and resets
- Role changes

**Filters:** Search by action type, member name, or date. Results are sorted newest first.

---

## 11. Log Viewer

> Accessible by: **Admin**, **Secretary**

Displays the live application log (`app.log`). Useful for diagnosing server errors or monitoring activity. Defaults to the last 200 lines. Use **Refresh** to reload.

---

## 12. Site Maintenance

> Accessible by: **Admin** only

### Test Email

Send a test email to verify that the email delivery system is functioning correctly. Enter a recipient address and click **Send Test Email**.

### Database Backup

Click **Download Backup** to download a full PostgreSQL dump of the database. Store backups securely offline.

### Maintenance Mode

Toggling maintenance mode displays a maintenance notice to all public visitors while allowing admin access to continue.

---

## 13. Security

### Login Protection

- After **5 failed login attempts**, the account is locked for **10 minutes**.
- Every failed login triggers an **email and SMS alert** to the account holder.
- Every admin login (success or failure) triggers an alert email to `ucosa.northamerica@gmail.com`.
- Every password change triggers a confirmation email and SMS to the account holder.

### Tokens

- JWT sessions expire after **8 hours**.
- Temporary passwords expire — members must change them on first login.

### Best Practices

- Never share admin credentials.
- Use strong, unique passwords.
- Log out when finished on shared computers.
- Review the Audit Log regularly for unusual activity.
- If you suspect a compromise, use **Lock Account** immediately and contact the system administrator.

---

## 14. Automated Scheduler

The server runs scheduled jobs automatically:

| Date | Time (ET) | Job |
|---|---|---|
| January 1st | 12:01 AM | Create annual dues records ($100 each) for all members for the new year with due date June 4. |
| May 4th | 9:00 AM | Send 30-day advance dues reminder (email + SMS) to all unpaid/partial members. |
| June 4th | 9:00 AM | Send due-date dues reminder (email + SMS) to all unpaid/partial members. |

No manual action is required for these jobs. They run silently and log results to the application log.

---

*UCOSA-NA Admin Manual — Last updated May 2026*
