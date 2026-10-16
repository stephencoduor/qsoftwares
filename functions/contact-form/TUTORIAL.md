# Set up the QSOFTWARES contact form

This creates a free Google Cloud function that emails the website's contact forms to you through Zoho.

Before you start, create a Zoho app password: in Zoho, go to **My Account → Security → App Passwords** and name it "Website".

## Run the setup

Click the copy button on the command below, then press Enter in the terminal.

```bash
bash functions/contact-form/setup-cloudshell.sh
```

When asked, type your Zoho mailbox and the app password. The password stays hidden while you type it.

The whole run takes about 3 minutes. It ends by printing the function's address.

## Finished

Leave the window open. Claude reads the address from your screen and connects the website forms to it.
