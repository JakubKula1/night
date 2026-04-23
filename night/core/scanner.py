import importlib
import pkgutil
import night.rules
import night.helpers.nginx_defaults


def load_rules():
    loaded_modules = []

    for _, module_name, _, in pkgutil.iter_modules(night.rules.__path__):
        module = importlib.import_module(f"night.rules.{module_name}")

        if hasattr(module, 'check') and callable(module.check):
            loaded_modules.append(module)

    return loaded_modules


class Scanner:
    def __init__(self, parsed_payload):
        self.payload = parsed_payload
        self.results = []
        self.rule_modules = load_rules()
        self.directives = night.helpers.nginx_defaults.main()

    def run_all_checks(self):
        for config_file in self.payload['config']:
            file_path = config_file['file']
            parsed_ast = config_file['parsed']

            for module in self.rule_modules:
                findings = module.check(parsed_ast, file_path)
                self.results.extend(findings)

        return self.results