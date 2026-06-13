// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

// Default Noombat CV template.
//
// This template receives profile data (experience, education, skills,
// publications) as Typst variables and produces a professional PDF.

#let name = "Name"
#let title = "Professional Title"

#set document(title: name + " — CV")
#set page(margin: 2cm)
#set text(font: "Libertinus Serif", size: 11pt)

= #name

#emph(title)

// Sections will be injected here by the CV generation pipeline.
