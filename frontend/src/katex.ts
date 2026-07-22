// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

// Standalone KaTeX CSS entry point.
//
// Imported by Vite to produce /assets/katex.css, which is loaded on
// server-rendered article pages that contain KaTeX htmlAndMathml
// output. The editor island imports the same CSS through its own
// bundle (editor/index.tsx); this entry point exists so that the
// read-only article view can load the stylesheet without pulling in
// the editor's JavaScript.
import "katex/dist/katex.min.css";
