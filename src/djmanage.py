#!python3
"""
Deployment script for Django projects.
This script is meant to run on a cron, and can also be run manually.

- stop
- start
- restart
- backup
- deploy
- check (for updates and deploy if available)

Use cases:
- Deploy a new Django project from scratch into a brand new directory.
- Deploy a new version of an existing project that is running.
- Stop or restart running services in a previously deployed project.
- Roll back to a previous deployment
- Perform a full backup of project data

What it does:
- Create a directory structure to house Project deployments
- Check disk space and abort if not enough free
- Fetch and install source code from a URL or local file
- Get or create a virtual environment with all dependencies
- Stop running processes (celery, gunicorn)
- Back up data
- Start new processes
"""
import argparse
import grp
import hashlib
import logging
import os
import random
import shutil
import subprocess
import sys
import textwrap
import time
import typing as T
import venv
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from dotenv import dotenv_values
from psutil import Process, TimeoutExpired, disk_usage, pid_exists
from rich.console import Console
from rich.logging import RichHandler

__version__ = "0.0.1"


###################################################################################
class NoLocationGivenError(Exception):
    pass


class CodeArchiveNotFoundError(Exception):
    pass


class UnsupportedArchiveTypeError(Exception):
    pass


###################################################################################
class DeployManager:
    """Manage deployments of a Django project."""

    def __init__(self, args) -> None:
        # Parse command line and set self.options
        self._parse_args(args)

        logging.basicConfig(
            level=logging.INFO,
            format="%(message)s",
            datefmt="[%X]",
            handlers=[RichHandler(rich_tracebacks=True)],
        )
        self.logger = logging.getLogger("deploy")
        self.console = Console()

        self.APP_HOME: Path = self.options.app_home.resolve()
        self.logger.info(f"Got app home of {self.APP_HOME}")

        # Save some paths. We don't create them here because they may already exist, or
        # they may not be needed depending on the operation.
        self.deployments_dir = self.APP_HOME / "deployments"
        self.downloads_dir = self.APP_HOME / "downloads"
        self.venvs_dir = self.APP_HOME / "venvs"
        self.data_dir = self.APP_HOME / "var"
        self.backups_dir = self.APP_HOME / "backups"

        self.celery_pidfile = self.data_dir / "run" / "celery.pid"
        self.celery_logfile = self.data_dir / "log" / "celery.log"
        self.gunicorn_pidfile = self.data_dir / "run" / "gunicorn.pid"
        self.gunicorn_accesslog = self.data_dir / "log" / "gunicorn_access.log"
        self.gunicorn_errorlog = self.data_dir / "log" / "gunicorn_error.log"
        self.pip_log = self.APP_HOME / "pip.log"
        self.down_for_maintenance_file = (
            self.data_dir / "docroot" / "DOWN-FOR-MAINTENANCE"
        )

        self.deploy_dir = None
        if self.options.command_name not in ["deploy", "install"]:
            # Command operates on an existing deploy directory, find current one.
            current_deploy = self.deployments_dir.joinpath("current")
            if current_deploy.exists():
                deploy_dir = current_deploy.resolve(strict=True)
                # if the link points to somewhere outside deployments_dir, this will
                # raise ValueError, preventing security violation
                _ = deploy_dir.relative_to(self.deployments_dir)
                self.deploy_dir = deploy_dir

        self.venv = None
        self.venv_python = None
        if self.deploy_dir:
            existing_venv = self.deploy_dir.joinpath("venv").resolve()
            if existing_venv.exists():
                self.venv = existing_venv
                self.venv_python = self.venv / "bin" / "python"

        if not self.options.servicegroup:
            grps_avail = os.getgroups()
            grps_by_name = {grp.getgrgid(x)[0]: x for x in grps_avail}
            if "www-data" in grps_by_name:
                self.options.servicegroup = "www-data"
            else:
                self.options.servicegroup = grp.getgrgid(grps_avail[0])[0]

        self.celery_opts = [
            "-A",
            self.APP_HOME.name,
            "worker",
            "-B",  # -B have the worker node start and manage beat
            "--pidfile",
            self.celery_pidfile.as_posix(),
            "--logfile",
            self.celery_logfile.as_posix(),
            "--loglevel",
            "INFO",
            "--umask",
            "002",
            "--time-limit",
            "300",
            "--soft-time-limit",
            "240",
            "--concurrency",
            "2",
            "-O",
            "fair",
        ]

        # NOTE: gunicorn binds to 127.0.0.1:8000 by default.
        self.gunicorn_opts = [
            "-p",
            str(self.gunicorn_pidfile),
            "--workers",
            "4",
            # https://docs.gunicorn.org/en/latest/faq.html#blocking-os-fchmod
            "--worker-tmp-dir",
            "/dev/shm",
            "--access-logfile",
            str(self.gunicorn_accesslog),
            "--error-logfile",
            str(self.gunicorn_errorlog),
        ]

    ###################################################################################
    def main(self):
        """Determine action to take and take it"""
        if self.options.command:
            return self.options.command()
        return self.status()

    ###################################################################################
    def install(self, release: T.Union[str, None] = None):
        """Fetches and installs a code archive, and creates a virtualenv for it."""
        # Check available disk space. ABORT if not sufficient.
        self._check_disk_space()
        # - Ensure the APP_HOME directory structure is created and has the correct permissions.
        self._create_dirs()
        # Make directory deployments/{datetime} for this release. It's an error if it
        # already exists.
        if release is None:
            release = self._generate_release_tag()
        self.deploy_dir = self.deployments_dir / release
        self.deploy_dir.mkdir()

        archive = self._get_archive(self.options.code_archive)
        self._extract_archive(archive, self.deploy_dir)
        venv = self._get_or_create_virtualenv()
        # Create a symlink in the deploy dir that points to its virtual env
        vlink = self.deploy_dir / "venv"
        vlink.symlink_to(venv)

    ###################################################################################
    def release(self, release: T.Union[str, None] = None):
        """Make a specific release tag "live"."""
        if release is None:
            release = self.options.release_tag
        if not self.deploy_dir:
            self.deploy_dir = self.deployments_dir / release
        if not self.deploy_dir.exists():
            print(f"Release tag {release} does not exist.")
            exit(1)

        if not self.venv:
            VV = self.deploy_dir.joinpath("venv")
            self.venv = VV.resolve()
            self.venv_python = self.venv / "bin" / "python"

        # Run any pre-release scripts that are safe while services are running.
        self._pre_release()
        # Stop running services. Puts site into maintenance mode.
        self.stop_services()
        # Run Data Backup. If backup fails, restart services without swapping symlink.
        try:
            self._make_data_backup()
        except Exception as e:
            self.start_services()
            raise e

        # At this point we are buggering shared data, and rollbacks will require restoring
        # our backup.

        # SWAP symlinks: old CURRENT becomes new PREVIOUS. DEPLOY_DIR becomes new CURRENT.
        # FIXME Don't overwrite previous when redeploying the same release tag.
        current = self.deployments_dir / "current"
        previous = self.deployments_dir / "previous"
        if current.is_symlink():
            if previous.is_symlink():
                previous.unlink()
            previous.symlink_to(current.resolve())
            current.unlink()
        current.symlink_to(self.deploy_dir)

        # Run migrate
        with self.console.status("Applying database migrations...", spinner="line"):
            self._manage("migrate", "--no-input")
        # Run generate_configs (future feature)
        # Install Apache config and check syntax. (future feature)
        # Reload Apache. (future feature)
        # Start services again
        self.start_services()

    ###################################################################################
    # Called for both "install" and "deploy" where "deploy" is "install" + "release"
    def deploy(self):
        release = self._generate_release_tag()
        self.install(release=release)
        if self.options.command_name == "install":
            return
        self.release(release=release)

    ###################################################################################
    def stop_services(self):
        """Stop running services and install the "down for maintenance" Apache config"""
        if not self.data_dir.exists():
            self.logger.error(
                f"Missing data directory, cannot continue. ({self.data_dir})"
            )
            return

        # Stop celery first. Long-running jobs may take a while to complete, but web site
        # remains responsive. Jobs will accumulate in the queue until the deploy completes.
        self.logger.info("Stopping celery.")
        if self.celery_pidfile.exists():
            graceful_stop(self.celery_pidfile, timeout=60)
        else:
            self.logger.warn("No celery PID file, assuming it's not running.")

        # DOWNTIME BEGINS. Install "Down for maintenance" Apache config.
        self.logger.info("Installing 'down for maintenance' notice")
        self.down_for_maintenance_file.touch()

        # Stop gunicorn.
        self.logger.info("Stopping gunicorn.")
        if self.gunicorn_pidfile.exists():
            graceful_stop(self.gunicorn_pidfile)
        else:
            self.logger.warn("No gunicorn PID file, assuming it's not running.")

        self.logger.info("Services stopped.")

    ###################################################################################
    def start_services(self):
        """Start services for the current deployment."""
        if not self.data_dir.exists():
            self.logger.error(
                f"Missing data directory, cannot continue. ({self.data_dir})"
            )
            return

        env = self._get_env_vars()
        wsgi = next(self.deploy_dir.glob("*/wsgi.py"))

        # Both processes daemonize, so these commands should return success immediately

        self.logger.info("Starting gunicorn.")
        gunicorn = self.venv / "bin" / "gunicorn"
        try:
            subprocess.run(
                [str(gunicorn), "-D", f"{wsgi.parent.name}.wsgi"],
                cwd=str(self.deploy_dir),
                check=True,
                capture_output=True,
                env=env,
            )
        except subprocess.CalledProcessError as e:
            self.console.print(e.output)
            self.console.print(e.stderr)
            exit(e.returncode)

        celery = self.venv / "bin" / "celery"
        if celery.exists():
            self.logger.info("Starting celery.")
            subprocess.run(
                [str(celery), "${CELERY_OPTS}", "-D"],
                cwd=str(self.deploy_dir),
                check=True,
                env=env,
            )
        else:
            self.logger.warn("No celery command found in virtual env, skipping celery.")

        # To guard against instacrash after daemonizing, sleep a bit and then check
        # that the processes are running.
        with self.console.status("Waiting for daemons to spawn...", spinner="line"):
            time.sleep(5.0)

        if not self.gunicorn_pidfile.exists():
            self.logger.error(f"No pidfile at {self.gunicorn_pidfile}")
            self.logger.error(f"Something went wrong. Bailing.")
            exit(4)
        if not pid_exists(int(self.gunicorn_pidfile.read_text())):
            self.logger.error("Gunicorn appears to have crashed! Bailing.")
            exit(3)
        if celery.exists():
            if not self.celery_pidfile.exists():
                self.logger.error(f"No pidfile at {self.celery_pidfile}")
                self.logger.error(f"Something went wrong. Bailing.")
                exit(2)
            if not pid_exists(int(self.celery_pidfile.read_text())):
                self.logger.error("Celery appears to have crashed! Bailing.")
                exit(1)

        # Situation normal. Remove the "down for maintenance" notice.
        if self.down_for_maintenance_file.exists():
            self.down_for_maintenance_file.unlink()
        self.logger.info("Processes up and running.")

    ###################################################################################
    def backup(self):
        pass

    ###################################################################################
    def config(self):
        "Check for or generate a .env file for the application."
        dotenv = self.APP_HOME / ".env"
        env = dotenv_values(str(dotenv))
        if env:
            self.console.print(env)
            return

        self.logger.info(f"No .env found, generating at {dotenv}")
        # TODO Allowed Hosts needs to be configurable, synced with Sites table and
        # Apache config.
        env = f"""
        ALLOWED_HOSTS="127.0.0.1,localhost"
        CELERY_OPTS="{" ".join(self.celery_opts)}"
        CELERY_TASK_ALWAYS_EAGER=False
        DATA_DIR="{self.data_dir}"
        GUNICORN_CMD_ARGS="{" ".join(self.gunicorn_opts)}"
        LOG_FILE="{self.data_dir / "log" / "django.log"}"
        SECRET_KEY="{self._generate_secret_key()}"
        """
        env = textwrap.dedent(env)

        dotenv.write_text(env)
        self.console.print(env)
        self.console.print("Sample configuration has been written to {dotenv}.")
        self.console.print(
            "Edit the configuration for your environment before starting services."
        )

    ###################################################################################
    def status(self):
        if self.deploy_dir:
            self.console.print(f"Current Release: {self.deploy_dir.name}")
            if self.gunicorn_pidfile.exists():
                gpid = int(self.gunicorn_pidfile.read_text())
                if pid_exists(gpid):
                    self.console.print(
                        f"Gunicorn is running (pid: {gpid})", style="green"
                    )
                else:
                    self.console.print(
                        f"Gunicorn apparently crashed! (pid: {gpid} is not running)",
                        style="red",
                    )
            else:
                self.console.print("Gunicorn is not running.", style="yellow")

        else:
            self.console.print(f"{self.APP_HOME.name} has never been deployed.")

        self.console.print(
            f"Data files will be owned by group: {self.options.servicegroup}"
        )

    ###################################################################################
    def print(self):
        val = getattr(self, self.options.var_to_print)
        if isinstance(val, list):
            print(" ".join(val))
            return
        print(val)

    ###################################################################################
    def _pip(self, *args):
        subprocess.run(
            [
                self.venv_python,
                "-m",
                "pip",
                "--no-input",
                "-qq",
                "--log",
                str(self.pip_log),
                *args,
            ],
            check=True,
            capture_output=True,
        )

    ###################################################################################
    def _manage(self, *args):
        assert self.venv_python
        assert self.deploy_dir
        subprocess.run(
            [str(self.venv_python), "manage.py", *args],
            cwd=str(self.deploy_dir),
            check=True,
            capture_output=True,
            env=self._get_env_vars(),
        )

    ###################################################################################
    def _check_disk_space(self):
        """Raises an Exception if there is not enough disk space to deploy safely"""
        # TODO Make disk space requirement configurable.
        # FIXME Account for 5% space reserved for system
        # https://github.com/giampaolo/psutil/blob/master/psutil/_psposix.py

        # Create the APP_HOME (we need an existing path to check disk usage)
        self.APP_HOME.mkdir(mode=0o775, parents=True, exist_ok=True)

        disk = disk_usage(self.APP_HOME)
        if disk.percent >= 90 or disk.free < 250 * 1024 * 1024:
            raise Exception("Low disk space, aborting.")

    ###################################################################################
    def _check_for_updates(self, sentinal: Path = None) -> str:
        if not sentinal:
            sentinal = self.data_dir / "log" / "deploy.next"
        if sentinal.exists():
            return sentinal.read_text().strip()
        return ""
        # raise NoLocationGivenError("No deploy.next file to locate code archive.")

    ###################################################################################
    def _create_dirs(self):
        """Create the application directory structure and set proper permissions.

        APP_HOME
         - backups | data archives
         - deployments | contains a subdir containing the code for each deployment
         - downloads | downloaded code archives
         - venvs | virtual environments for deployments
         - var | all files used by the running application (backup target)
          - db | sqlite database files, WRITABLE by App
          - docroot | Apache document root, READ-ONLY by App
          - log | log files, WRITABLE by App
          - media | uploaded media, WRITABLE by App
          - run | pid files, WRITABLE by App
          - static | target of collectstatic, READ-ONLY by App
        """
        self.logger.info(f"Creating deployment root at {self.APP_HOME}")
        with self.console.status("Checking directory structure.", spinner="line"):
            self.APP_HOME.mkdir(mode=0o775, parents=True, exist_ok=True)

            self.backups_dir.mkdir(exist_ok=True)
            self.deployments_dir.mkdir(exist_ok=True)
            self.downloads_dir.mkdir(exist_ok=True)
            self.venvs_dir.mkdir(exist_ok=True)

            self.data_dir.mkdir(mode=0o775, exist_ok=True)
            # These subdirs should be read-only by the running app for security
            for subdir in ["docroot", "static"]:
                target = self.data_dir.joinpath(subdir)
                target.mkdir(mode=0o755, exist_ok=True)

            # These subdirs must be writable by the App processes
            for subdir in "db log media run".split():
                target = self.data_dir.joinpath(subdir)
                target.mkdir(exist_ok=True)
                shutil.chown(target.as_posix(), group=self.options.servicegroup)
                target.chmod(0o2775)  # setgid bit so all files have same group

    ###################################################################################
    def _disk_usage(self) -> dict:
        "Return a structure describing disk usage for subdirectories in APP_HOME"
        dirdata = {}
        with self.console.status("Checking disk space used.", spinner="line"):
            output = subprocess.check_output(
                ["/usr/bin/du", "-sh", *[x.name for x in self.APP_HOME.glob("*")]],
                cwd=str(self.APP_HOME),
            )
            for line in output.decode().strip():
                key, val = line.split(maxsplit=1)
                dirdata[key] = val
        return dirdata

    ###################################################################################
    def _extract_archive(self, archive: Path, dest: Path):
        # - Extract the archive into DEPLOY_DIR. We shell out to tar rather than using
        # shutil.extract_archive because tar is less stupid about security issues (see
        # security warning at https://docs.python.org/3/library/shutil.html#shutil.unpack_archive)
        self.logger.info(f"Extracting archive {archive}")
        with self.console.status("Extracting archive."):
            subprocess.check_call(
                [
                    "tar",
                    "-C",  # change dir into
                    str(dest),  # deploy dir first
                    "--strip-components",  # remove one component from path
                    "1",  # the leading app_name, we replaced with DEPLOY_DIR
                    "-xzf",  # decompress and extract
                    str(archive),
                ],
            )

    ###################################################################################
    def _generate_release_tag(self) -> str:
        return datetime.now().strftime("%Y%m%d-%H%M")

    ###################################################################################
    def _generate_secret_key(
        self,
        length=72,
        allowed_chars="abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        "/.,@^-_=+",
    ):
        return "".join(random.choice(allowed_chars) for i in range(length))

    ###################################################################################
    def _get_archive(self, location: str) -> Path:
        """
        Locates (and potentially downloads) your archive, returning the local path as a
        ``pathlib.Path``.
        """
        # Retrieve the code archive for the specified release.
        # if not location.endswith(".gz"):
        #     raise UnsupportedArchiveTypeError(
        #         "Archives must be compressed as .gz files."
        #     )

        # Parse as a URL, but default to file scheme for passing a local path
        archive = None
        url = urlparse(location, scheme="file")
        if url.scheme == "file":
            archive = Path(location).resolve()
            if not archive.exists():
                raise CodeArchiveNotFoundError(
                    f"No archive found at location {archive}"
                )
            return archive

        # The location is a remote URL. Retrieve it and store in the local file system.
        archive = self.downloads_dir / Path(url.path).name
        self.logger.info(f"Retrieving URL {url.geturl()}")
        with self.console.status("Retrieving remote archive.", spinner="line"):
            subprocess.check_call(
                ["/usr/bin/curl", "-s", "-L", "-o", str(archive), url.geturl()]
            )
        return archive

    ###################################################################################
    def _get_env_vars(self) -> T.Union[dict, None]:
        dotenv = self.APP_HOME / ".env"
        if not dotenv.exists():
            self.logger.error(f"Missing environment file at {dotenv}")
            self.console.print(
                f"Commands cannot run without an environment file.", style="red"
            )
            self.console.print(f"You need to create one at {dotenv}", style="red")
            self.console.print(
                f"Hint: create one with djmanage {self.APP_HOME.name} config",
                style="yellow",
            )
            return None
        return dotenv_values(str(dotenv))

    ###################################################################################
    def _get_or_create_virtualenv(self) -> Path:
        # Create the virtual env if it does not already exist. We can reuse an existing
        # virtualenv to save time, IF it used the exact same requirements.txt AND the same
        # Python interpreter.

        # - Hash the requirements.txt.
        REQS = self.deploy_dir.joinpath("requirements.txt")
        msg = hashlib.sha1()
        msg.update(REQS.read_bytes())  # add contents of requirements.txt
        # add python version. Changing interpreters requires new venv.
        msg.update(sys.version.encode())
        self.venv = self.venvs_dir / msg.hexdigest()[:8]
        self.venv_python = self.venv / "bin" / "python"

        if not self.venv.joinpath("success").exists():
            # The venv does not exist or did not complete installation last time.
            self.logger.info(f"No virtualenv matches, creating {self.venv}")
            with self.console.status("Creating virtual environment.", spinner="line"):
                # Create a new virtualenv, clearing any detritus from any previous runs
                venv.create(self.venv.as_posix(), clear=True, with_pip=True)
            # The --upgrade-deps argument to venv was added in 3.9, but we support 3.8,
            # so we upgrade pip the old fashioned way.
            with self.console.status("Checking for latest pip.", spinner="line"):
                self._pip("install", "--upgrade", "pip", "wheel")
            # Install app requirements
            with self.console.status(
                "Installing project requirements (may take a bit).", spinner="line"
            ):
                self._pip("install", "-r", str(REQS))
            # If all the above completed, we mark virtualenv creation success
            self.venv.joinpath("success").touch()
            self.logger.info(f"Successfully created venv in {self.venv}")

        return self.venv

    ###################################################################################
    def _pre_release(self):
        "Commands to run before stopping services on the old release."
        # FIXME Assumes staticfiles in INSTALLED_APPS.
        # It should be MOSTLY safe to do this while online if using Manifest Storage.
        # Files that have changed will have a different hash and not overwrite existing
        # files. The manifest is not touched until the end, when it is first deleted and
        # then saved, so there's a brief window where errors could occur. If using the
        # plain Static Storage, changed files will overwrite, which could cause JS and
        # CSS to be out of sync with the templates (which won't change until we swap
        # the current release).
        try:
            with self.console.status("Collecting static files...", spinner="line"):
                self._manage("collectstatic", "--no-input")
        except subprocess.CalledProcessError as e:
            self.console.print(
                f"Management command 'collectstatic' failed.", style="red"
            )
            self.console.print(e.output)
            self.console.print(e.stderr)
            exit(e.returncode)

    ###################################################################################
    def _make_data_backup(self):
        "Copy data to local backup location."
        self.logger.warn("Backup is not implemented.")

    ###################################################################################
    def _parse_args(self, args):
        argparser = argparse.ArgumentParser()
        argparser.add_argument(
            "--servicegroup",
            action="store",
            help=(
                "The name of the group who will own the running processes. Default: "
                "www-data. Files that need to be writable by services will belong to "
                "this group, and directories will have the setgid bit set."
            ),
        )
        argparser.add_argument(
            "--serviceuser",
            action="store",
            help=(
                "The name of the user who will own the running processes. Typically "
                "a non-privileged user. Default: www-data. Note that the user "
                "running this program must have sudo privilege to become the "
                "serviceuser."
            ),
        )
        argparser.add_argument("app_home", type=Path, help="The path to manage.")
        argparser.set_defaults(command=None)

        commands = argparser.add_subparsers(title="commands", dest="command_name")

        # STATUS
        cmd_status = commands.add_parser(
            "status", help="Report status of current deployment."
        )
        cmd_status.set_defaults(command=self.status)

        # CONFIG
        cmd_config = commands.add_parser("config", help="Back up app data.")
        cmd_config.set_defaults(command=self.config)

        # START
        cmd_start = commands.add_parser(
            "start",
            help="Start running services for the current deployment.",
        )
        cmd_start.set_defaults(command=self.start_services)

        # STOP
        cmd_stop = commands.add_parser(
            "stop",
            help="Stop running services for the current deployment.",
        )
        cmd_stop.set_defaults(command=self.stop_services)

        # RESTART
        # cmd_restart = commands.add_parser(
        #     "restart",
        #     help="Restart or start running services for the current deployment.",
        # )

        # BACKUP
        cmd_backup = commands.add_parser("backup", help="Back up app data.")
        cmd_backup.set_defaults(command=self.backup)
        cmd_backup.add_argument(
            "--stop",
            action="store_true",
            dest="stop_on_backup",
            default="false",
        )

        # DEPLOY
        cmd_deploy = commands.add_parser(
            "deploy", aliases=["install"], help="Deploy new code"
        )
        cmd_deploy.add_argument(
            "code_archive",
            action="store",
            metavar="CODE_ARCHIVE",
            help="A file or URL to be installed and deployed.",
        )
        cmd_deploy.set_defaults(command=self.deploy)

        cmd_release = commands.add_parser(
            "release", help="Make a specific release tag the 'live' release."
        )
        cmd_release.add_argument(
            "release_tag",
            action="store",
            metavar="RELEASE",
            help="The deployment (from APP_HOME/deployments/) to make live.",
        )
        cmd_release.set_defaults(command=self.release)

        cmd_print = commands.add_parser("print", help="Back up app data.")
        cmd_print.set_defaults(command=self.print)
        cmd_print.add_argument(
            "var_to_print",
            action="store",
        )

        self.options = argparser.parse_args(args)


# Deploy steps:
# - if -e CURRENT:
#   - stop its services.
#   - Create rollback checkpoint: run backup of media, static, db, docroot.
#   - Test backup: ensure db file is correct size, same number of media files.
#   - Upload backup to S3.
#   - Symlink PREVIOUS to CURRENT's target.
# - Activate venv.
# - Run collectstatic
# - Run migrate
# - Run generate_configs
# - If new apache config, install it.
# - Symlink CURRENT to new release.
# - Start services. Wait. Test they started successfully.
# - Remove any release dir not pointed to by PREVIOUS or CURRENT.
# - Remove any venv not used by PREVIOUS or CURRENT.

# Rollback:

# - Stop services.
# - Make CURRENT link point to dest of PREVIOUS.
# - Restart services.


def graceful_stop(pidfile: Path, timeout=5):
    """Given a pidfile, stop the process that created it and remove the file."""
    pid = int(pidfile.read_text())
    if pid < 2:
        print(f"SECURITY ERROR: {pidfile} is corrupted!")
        exit(5)

    p = Process(pid=pid)
    if p.is_running():
        p.terminate()
        # Give it time to shut down gracefully
        try:
            p.wait(timeout=timeout)
        except TimeoutExpired:
            # kill it with fire
            p.kill()
    # When daemons exit cleanly, they usually clean up their own pidfile. JIC, do it
    # for them.
    pidfile.unlink(missing_ok=True)


def main():
    cmd = DeployManager(args=sys.argv[1:])
    cmd.main()


if __name__ == "__main__":
    main()
