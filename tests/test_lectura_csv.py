#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pruebas de regresion de la lectura de CSV.

POR QUE EXISTEN: una subida de pandas cambio el tipo que devuelve read_csv
con dtype=str (StringDtype en lugar de object). El codigo normalizaba solo
las columnas de dtype `object`, asi que los NaN de las columnas nuevas se
colaban y acababan impresos como el texto "nan" DENTRO del informe que se
entrega al cliente. Ademas rompian las mascaras booleanas del tipo
`.str.len() > 0`.

Esta regresion no la detecta nadie hasta que el informe ya esta entregado, y
llego por una actualizacion automatica de dependencias. Con Dependabot
fusionando parches solo, estas pruebas son el unico freno que hay entre una
subida de pandas y un entregable con "nan" impreso.

Se ejecutan con la biblioteca estandar, sin pytest:

    python -m unittest discover -s tests -v
"""
import sys
import tempfile
import unittest
from pathlib import Path

# El modulo vive en la raiz del repositorio, un nivel por encima de tests/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd  # noqa: E402
from informe_crem import _leer_csv_raw  # noqa: E402


class LecturaCsvTest(unittest.TestCase):
    def _csv(self, contenido: str, encoding: str = "utf-8") -> Path:
        """Escribe un CSV temporal y devuelve su ruta."""
        tmp = Path(tempfile.mkdtemp()) / "datos.csv"
        tmp.write_text(contenido, encoding=encoding)
        return tmp

    def test_celdas_vacias_no_producen_el_texto_nan(self):
        """Ninguna celda vacia puede acabar como la cadena "nan".

        Es la regresion concreta que se colo en un informe entregado.
        """
        ruta = self._csv(
            "cve,severidad,notas\n"
            "CVE-2024-0001,Critical,revisar\n"
            "CVE-2024-0002,,\n"
            ",High,\n"
        )
        df = _leer_csv_raw(ruta)

        planas = [str(v) for v in df.to_numpy().ravel()]
        self.assertNotIn("nan", planas, "una celda vacia se convirtio en el texto 'nan'")
        self.assertNotIn("NaN", planas)
        self.assertNotIn("<NA>", planas)

    def test_las_celdas_vacias_son_cadena_vacia(self):
        ruta = self._csv("a,b\n1,\n,2\n")
        df = _leer_csv_raw(ruta)
        self.assertEqual(df.loc[0, "b"], "")
        self.assertEqual(df.loc[1, "a"], "")

    def test_todas_las_columnas_admiten_el_accesor_str(self):
        """`.str.len() > 0` es la mascara que usa el generador de informes.

        Sobre una columna que no sea de texto lanza excepcion o devuelve NA,
        que es justo como se manifestaba el fallo aguas abajo.
        """
        ruta = self._csv("cve,vacia\nCVE-2024-0001,\nCVE-2024-0002,\n")
        df = _leer_csv_raw(ruta)
        for col in df.columns:
            mascara = df[col].str.len() > 0
            self.assertEqual(len(mascara), len(df))
            self.assertTrue(mascara.dtype == bool, f"la mascara de '{col}' no es booleana")

    def test_las_columnas_son_de_tipo_texto(self):
        ruta = self._csv("numero,texto\n1,uno\n2,dos\n")
        df = _leer_csv_raw(ruta)
        for col in df.columns:
            self.assertTrue(
                all(isinstance(v, str) for v in df[col]),
                f"la columna '{col}' contiene valores que no son str",
            )

    def test_se_limpia_el_bom_de_las_cabeceras(self):
        """Los CSV exportados desde Vision One llegan con BOM."""
        ruta = self._csv("﻿cve,severidad\nCVE-2024-0001,High\n")
        df = _leer_csv_raw(ruta)
        self.assertIn("cve", df.columns)
        self.assertFalse(any(c.startswith("﻿") for c in df.columns))

    def test_se_recortan_los_espacios_de_las_cabeceras(self):
        ruta = self._csv("  cve  ,  severidad  \nCVE-2024-0001,High\n")
        df = _leer_csv_raw(ruta)
        self.assertIn("cve", df.columns)
        self.assertIn("severidad", df.columns)

    def test_un_fichero_inexistente_devuelve_dataframe_vacio(self):
        """No debe lanzar excepcion: el flujo continua sin ese CSV."""
        df = _leer_csv_raw(Path(tempfile.mkdtemp()) / "no-existe.csv")
        self.assertIsInstance(df, pd.DataFrame)
        self.assertTrue(df.empty)

    def test_las_filas_totalmente_vacias_se_descartan(self):
        ruta = self._csv("a,b\n1,2\n,\n3,4\n")
        df = _leer_csv_raw(ruta)
        self.assertEqual(len(df), 2)

    def test_csv_en_latin1(self):
        """Vision One exporta a veces en latin-1; no debe romper la lectura."""
        ruta = self._csv("host,descripcion\nSRV01,Servidor de administración\n", encoding="latin-1")
        df = _leer_csv_raw(ruta)
        self.assertEqual(len(df), 1)
        self.assertIn("host", df.columns)


if __name__ == "__main__":
    unittest.main(verbosity=2)
