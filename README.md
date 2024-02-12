# ArcRADIUS

ArcRADIUS is a RADIUS provider service designed to authenticate users and provide secure access control.

## Features

- **Secure Authentication:** ArcRADIUS provides secure authentication for network access using the RADIUS protocol.
- **OTP Support:** Support for One-Time Passwords (OTP) enhances security by adding an extra layer of authentication.
- **Easy Integration:** Easily integrate ArcRADIUS with existing systems and infrastructure.
- **Scalability:** ArcRADIUS is designed to handle large numbers of users and can scale according to your needs.
- **Configurable Policies:** Configure access control policies to suit your organization's requirements.

## Installation

To install ArcRADIUS, follow these steps:

1. **Disable FreeRadius:** Before installing ArcRADIUS, make sure to disable FreeRadius:

```bash
sudo systemctl stop freeradius.service
sudo systemctl disable freeradius.service
```

2. Install ArcRADIUS: Download the latest release from the Releases page and follow the installation instructions provided.

3. Configure Client Address: Configure the client address in the **Edit Address** tab of the ArcRADIUS admin panel.

4. Restart ArcRADIUS: Restart the ArcRADIUS service to apply the changes:

```bash
sudo systemctl restart arc-radius.service
```

5. Create User Account: Create a user account for the RADIUS client in the **User** tab of the ArcRADIUS admin panel.

6. Generate OTP QR Code: Generate the user's OTP QR code by clicking the **Show QR code** button.
