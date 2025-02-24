import configparser

class AccessController:
    """
    A simple class that would be used to define and control access to resources based on user roles.
    """

    def __init__(self, config_file):
        self.roles = []
        self.resources = []
        self.permissions = []
        self.framework_specific_check = None
        self.load_config(config_file)

    def load_config(self, config_file: str):
        """Loads the access control configuration from a file.

        Args:
            config_file (str): The path to the configuration file.

        Raises:
            ValueError: If the configuration file is missing the 'roles', 'resources', or 'permissions' sections, or if an invalid permissions matrix is provided.
        """
        config = configparser.ConfigParser(allow_no_value=True, delimiters=('='))
        config.read(config_file)

        if 'roles' not in config or 'resources' not in config or 'permissions' not in config:
            raise ValueError("Config file must contain 'roles', 'resources', and 'permissions' sections")

        self.roles = [key.strip() for key in config['roles'].keys()]
        self.resources = [resource.strip() for resource in config['resources'].keys()]

        # Parse permissions as a matrix
        raw_permissions = list(config['permissions'].keys())
        self.permissions = [list(map(int, row.split(','))) for row in raw_permissions]

        if len(self.permissions) != len(self.roles) or any(len(row) != len(self.resources) for row in self.permissions):
            raise ValueError("Invalid permissions matrix: must match the number of roles and resources")

    def is_allowed(self, role: str, resource: str):
        """Enforces the access control policy. returns true if resource is accessible to role, false otherwise.

        Args:
            role (str): The role of the user. Must be one of the values defined in the configuration file.
            resource (str): The resource to be accessed. Must be one of the values defined in the configuration file.
        """

        # allows access to everyone for now.
        # update this to enforce the access control policy.

        if self.permissions[self.roles.index(role)][self.resources.index(resource)] == 1:
            return True
        else:
            return False
        