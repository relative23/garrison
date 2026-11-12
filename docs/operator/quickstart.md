# Quick start

The short way, for a host that already runs Stalwart (natively, or in Docker
or Podman in the host network), nginx and certbot (or another way to get
certificates). The [installation guide](installation.md)
explains every step and the choices behind it.

1. Download the archive for your architecture (`uname -m`) and its `.minisig`
   signature, and check it with the release signing key from the README:

   ```sh
   minisign -Vm garrison-<version>-<arch>.tar.gz -P <release signing key>
   ```

2. Install the release; this starts nothing yet, and links the `garrison`
   command into the search path:

   ```sh
   tar xzf garrison-<version>-<arch>.tar.gz
   sudo ./garrison-<version>-<arch>/bin/garrison install
   ```

3. Let Garrison ask what it needs: its own address, Stalwart's addresses, the
   modules and, once, a Stalwart administrator. It then connects Stalwart,
   grants Stalwart's administrators access, starts the services and prints the
   nginx server block for your host names:

   ```sh
   sudo garrison setup
   ```

4. Create the DNS record for Garrison's own host name and a certificate, save
   the printed server block as `/etc/nginx/conf.d/garrison.conf`, add the
   printed include to each server block that proxies to Stalwart, then:

   ```sh
   sudo nginx -t && sudo systemctl reload nginx
   ```

5. Check the whole installation; every problem comes with what to do:

   ```sh
   sudo garrison doctor
   ```

Open `https://<Garrison's host name>/admin/` and sign in with your Stalwart
account. Upgrades later take one command, `garrison upgrade`
([operations](operations.md#upgrade-and-rollback)). To get a message when a
check fails, name an ntfy topic
([installation, step 9](installation.md#9-notifications-optional)).
