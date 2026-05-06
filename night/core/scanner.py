import importlib
import pkgutil
import os
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
        self.raw_results = []
        self.results = []
        self.rule_modules = load_rules()
        self.directives = night.helpers.nginx_defaults.main()   # All found directives default values in a dict

    def run_all_checks(self):
        for config_file in self.payload['config']:
            file_path = config_file['file']
            parsed_ast = config_file['parsed']

            self._traverse(parsed_ast, file_path, self.directives.copy(), context_name="global")

        grouped_findings = {}
        for finding in self.raw_results:
            rule_id = finding.get('rule_id', 'UNKNOWN')
            raw_file = finding.get('file', '')
            file = os.path.abspath(raw_file) if raw_file else ''
            line = str(finding.get('line', ''))

            is_implicit = line in ["Inherited", "Default", "Inherited/Default", "N/A"]
            occurrence = {'file': file, 'line': line, 'is_implicit': is_implicit}

            if rule_id not in grouped_findings:
                grouped_findings[rule_id] = {
                    'rule_id': rule_id,
                    'rule': finding.get('rule'),
                    'description': finding.get('description'),
                    'occurrences': []
                }
            else:
                if not is_implicit:
                    grouped_findings[rule_id]['rule'] = finding.get('rule')
                    grouped_findings[rule_id]['description'] = finding.get('description')

            if occurrence not in grouped_findings[rule_id]['occurrences']:
                grouped_findings[rule_id]['occurrences'].append(occurrence)

        for rule_id, data in grouped_findings.items():
            final_occurrences = []
            occs_by_file = {}
            for occ in data['occurrences']:
                if occ['file'] not in occs_by_file:
                    occs_by_file[occ['file']] = []
                occs_by_file[occ['file']].append(occ)

            for file_path, occs in occs_by_file.items():
                explicit_occs = [o for o in occs if not o['is_implicit']]
                implicit_occs = [o for o in occs if o['is_implicit']]

                if explicit_occs:
                    final_occurrences.extend(explicit_occs)
                elif implicit_occs:
                    final_occurrences.append(implicit_occs[0])

            data['occurrences'] = final_occurrences
            self.results.append(data)

        return self.results

    def _traverse(self, block, file_path, current_state, context_name):
        """Core engine that 'walks' the AST and runs rule modules"""
        for directive in block:
            cmd = directive.get('directive')
            args = directive.get('args',[])

            if cmd in current_state.keys():
                if args:
                    current_state[cmd] = " ".join(args)

        for module in self.rule_modules:
            findings = module.check(block, file_path, current_state, context_name)
            if findings:
                self.raw_results.extend(findings)

        for directive in block:
            if 'block' in directive:
                new_context = directive.get('directive')
                self._traverse(directive['block'], file_path, current_state.copy(), new_context)