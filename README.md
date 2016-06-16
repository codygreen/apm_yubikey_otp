# Yubikey OTP with F5 Access Policy Manager
iRules to use Yubikey OTP with F5 Access Policy Manager

This iRules was updated to support APM and is based on  the DevCentral article: https://devcentral.f5.com/articles/two-factor-authentication-using-yubikey-yubicloud-and-big-ip-ltm

### Configuration
it uses an APM iRule event: otp_verify
This iRule event can be added the APM Visual Policy Editor after your user authentication

You'll need to create a data group (yubikey_users) to store username to serial mappings

You'll also need to assign the iRules to your virtual server
