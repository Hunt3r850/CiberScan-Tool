"""Generacion de informes para resultados de descubrimiento web."""

import datetime
import html
import json
import logging
import os


class DirectoryReporter:
    def __init__(self, output_dir="./output", log_level=logging.INFO):
        self.output_dir = output_dir
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_level)
        os.makedirs(output_dir, exist_ok=True)

    @staticmethod
    def _metadata(results, base_url):
        return {
            "generated_at": datetime.datetime.now().isoformat(),
            "target": base_url,
            "total": len(results),
            "success_count": sum(item.is_success() for item in results),
            "interesting_count": sum(item.interesting for item in results),
        }

    def generate_text_report(self, results, base_url, output_file=None):
        output_file = output_file or os.path.join(self.output_dir, "directory_report.txt")
        metadata = self._metadata(results, base_url)
        lines = [
            "INFORME DE ESCANEO DE DIRECTORIOS WEB",
            "=" * 42,
            f"Objetivo: {base_url}",
            f"Resultados: {metadata['total']}",
            f"Exitosos: {metadata['success_count']}",
            f"Interesantes: {metadata['interesting_count']}",
            "",
        ]
        for item in results:
            lines.append(f"[{item.status_code}] {item.url}")
            if item.notes:
                lines.append("  " + "; ".join(item.notes))
        with open(output_file, "w", encoding="utf-8") as output:
            output.write("\n".join(lines) + "\n")
        return output_file

    def generate_html_report(self, results, base_url, output_file=None):
        output_file = output_file or os.path.join(self.output_dir, "directory_report.html")
        metadata = self._metadata(results, base_url)
        rows = "".join(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                item.status_code,
                html.escape(item.url),
                "Si" if item.interesting else "No",
                html.escape("; ".join(item.notes)),
            )
            for item in results
        )
        document = f"""<!doctype html><html lang=\"es\"><meta charset=\"utf-8\">
<title>Informe de directorios</title><body><h1>Informe de escaneo de directorios web</h1>
<p><strong>Objetivo:</strong> {html.escape(base_url)}</p>
<p>{metadata['total']} resultados; {metadata['success_count']} exitosos; {metadata['interesting_count']} interesantes.</p>
<table border=\"1\"><thead><tr><th>Estado</th><th>URL</th><th>Interesante</th><th>Notas</th></tr></thead>
<tbody>{rows}</tbody></table></body></html>"""
        with open(output_file, "w", encoding="utf-8") as output:
            output.write(document)
        return output_file

    def generate_json_report(self, results, base_url, output_file=None):
        output_file = output_file or os.path.join(self.output_dir, "directory_report.json")
        with open(output_file, "w", encoding="utf-8") as output:
            json.dump(
                {"metadata": self._metadata(results, base_url), "results": [item.to_dict() for item in results]},
                output,
                ensure_ascii=False,
                indent=2,
            )
        return output_file

    def generate_complete_report(self, results, base_url, output_dir=None):
        if output_dir:
            self.output_dir = output_dir
            os.makedirs(output_dir, exist_ok=True)
        return {
            "text": self.generate_text_report(results, base_url),
            "html": self.generate_html_report(results, base_url),
            "json": self.generate_json_report(results, base_url),
        }
