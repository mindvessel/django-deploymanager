# 💿🎤💿 DJManage

Not for music DJ! Tool to manage simple single-server Django deployments.

Requires Python 3.8 or higher.

Warning: early alpha software. There will definitely be breaking changes in the future.
Use at your own risk.

## Installation

The tool is best installed at the user level on your deployment server, not as part of
your Django project. To install:

    pip install --user djmanage

This will install the `djmanage` command for the user, which you can then use to install
and setup your Django project.

## Managing Deployments

Say you have a Django project in a git repo, and you want to deploy it to a cloud VM.

Step 1: Package your project files in a `.tar.gz` archive (at present ONLY tarballs are
supported).

Step 2. Shell into your server and install DJManage (as above).

Step 3. `djmanage /home/django/MYPROJECT install TARBALL`

This will create a directory structure under the directory `/home/django/MYPROJECT`,
download the tarball, extract it to a deployment directory, create a Python virtual
environment for it, and pip install your `requirements.txt`.

Step 4. Run `djmanage MYPROJECT config` to create a `.env` file in MYPROJECT for your
environment-specific settings. Edit the file to add or adjust your own settings.

Step 5: Run `djmanage MYPROJECT release DEPLOYMENT_DIR` to start gunicorn and celery (if
you use it).

## DJManage Commands

The first argument to `djmanage` is always the directory you want it to manage.
Following this should be one of the following commands.

- `status` - Some useful info about this project.
- `install ARCHIVE.tar.gz` - Installs a new code archive and prepares it for deployment.
- `release DEPLOY_DIR` - Takes a specific deployment "live".
- `deploy ARCHIVE.tar.gz` - Performs `install` followed immediately by `release`. Use
  this if you have already created your configuration and want to upgrade to a newer
  code release.
- `stop` - Stop the running services for this project. Puts the site into "Maintenance
  Mode".
- `start` - Start the services for this projects. Takes the site out of "Maintenance
  Mode".
- `config` - Prints the `.env` configuration used for this project. If that
  configuration file does not exist, it will generate one with useful default values.
