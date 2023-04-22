from unittest import TestCase
from unittest.mock import patch

from djmanage import DeployManager


class TestInstance(TestCase):
    def test_paths(self):
        dm = DeployManager(["var/test_paths"])
        self.assertIsNone(dm.deploy_dir)
        self.assertIsNone(dm.venv)
        self.assertFalse(dm.data_dir.exists())

    def test_default_command(self):
        dm = DeployManager(["var/test_not_there"])
        self.assertIsNone(dm.options.command_name)
        self.assertIsNone(dm.options.command)
        with patch.object(dm, "status") as mock_status:
            dm.main()
            mock_status.assert_called_once()
