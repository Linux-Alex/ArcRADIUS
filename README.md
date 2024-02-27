# ArcRADIUS

![ArcRADIUS Logo](./assets/Logo.png)

ArcRADIUS is a RADIUS provider service designed to authenticate users and provide secure access control.

## Features

- **Secure Authentication:** ArcRADIUS provides secure authentication for network access using the RADIUS protocol.
- **OTP Support:** Support for One-Time Passwords (OTP) enhances security by adding an extra layer of authentication.
- **Easy Integration:** Easily integrate ArcRADIUS with existing systems and infrastructure.
- **Scalability:** ArcRADIUS is designed to handle large numbers of users and can scale according to your needs.
- **Configurable Policies:** Configure access control policies to suit your organization's requirements.

# ArcRADIUS

ArcRADIUS is a RADIUS provider service designed to authenticate users and provide secure access control.

## Pre-install Requirements

Before installing ArcRADIUS, make sure you have the following:

- **Operating System:** Ubuntu 22.04 or newer (or other Ubuntu-based distributions)

## Installation

To install ArcRADIUS, follow these steps:

1. **Disable FreeRadius:** Before installing ArcRADIUS, make sure to disable FreeRadius:

```bash
sudo systemctl stop freeradius.service
sudo systemctl disable freeradius.service
```

2. Install ArcRADIUS: Download the [latest release](https://github.com/Linux-Alex/ArcRADIUS/releases/tag/production) from the Releases page and follow the installation instructions provided.

3. Open the Web Admin Panle of ArcRADIUS on link: [https://localhost:4048](https://localhost:4048)

4. Click on the **Login** button in the top right corner and use the default credentials (username: `admin`, password: `admin`).

5. Configure Client Address: Configure the client address in the **RADIUS Clients** tab of the ArcRADIUS admin panel.

6. Restart ArcRADIUS: Restart the ArcRADIUS service to apply the changes:

```bash
sudo systemctl restart arc-radius.service
```

7. Create User Account: Create a user account for the RADIUS client in the **Accounts** and then **User Accounts** tab of the ArcRADIUS admin panel.

8. Generate OTP QR Code: Generate the user's OTP QR code by clicking the **Show QR code** button.
