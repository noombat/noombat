// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

// Default Noombat CV template.
//
// All variables are injected by the CV generation pipeline (cv.rs)
// before this file is appended.
// Do NOT declare #let bindings here: they would shadow the injected values.
//
// Expected variables:
//   name            : str
//   title           : str          (may be "")
//   summary         : content|none (none when absent)
//   orcid           : str          (may be "")
//   experiences     : array of dict(title, company, dates, description)
//   educations      : array of dict(institution, degree, field, dates, description)
//   skills          : array of str
//   publications    : array of dict(formatted, doi)
//   citation_style  : str          ("apa", "ieee", or "vancouver")
//   verified_links  : array of str

// ..... Page setup .....
#set document(title: name + " - Curriculum Vitae")
#set page(margin: (top: 2cm, bottom: 2cm, left: 2cm, right: 2cm))
#set text(font: "Libertinus Serif", size: 10.5pt, lang: "en")
#set par(justify: true)

// ..... Heading styles .....
#show heading.where(level: 1): it => {
  set text(size: 22pt, weight: "bold")
  it
  v(2pt)
}

#show heading.where(level: 2): it => {
  v(10pt)
  set text(size: 13pt, weight: "bold")
  line(length: 100%, stroke: 0.5pt + luma(180))
  v(2pt)
  it
  v(4pt)
}

// ..... Header .....
= #name

#if title != "" [
  #text(size: 12pt, style: "italic")[#title]
  #v(4pt)
]

#if orcid != "" [
  #text(size: 9pt, fill: luma(100))[ORCID: #link("https://orcid.org/" + orcid)[#orcid]]
  #v(2pt)
]

#if summary != none [
  #v(4pt)
  #summary
  #v(2pt)
]

// ..... Experience .....
#if experiences.len() > 0 [
  == Experience
  #for exp in experiences [
    *#exp.title*, #exp.company #h(1fr) #exp.dates
    #v(2pt)
    #if "description" in exp and exp.description != "" [
      #exp.description
    ]
    #v(6pt)
  ]
]

// ..... Education .....
#if educations.len() > 0 [
  == Education
  #for edu in educations [
    *#edu.institution* #h(1fr) #edu.dates
    #v(2pt)
    #if "degree" in edu and edu.degree != "" [
      #edu.degree
      #if "field" in edu and edu.field != "" [
        · #edu.field
      ]
      #v(2pt)
    ]
    #if "description" in edu and edu.description != "" [
      #edu.description
    ]
    #v(6pt)
  ]
]

// ..... Skills .....
#if skills.len() > 0 [
  == Skills
  #skills.join("  ·  ")
  #v(6pt)
]

// ..... Publications .....
#if publications.len() > 0 [
  == Publications
  #for pub_ in publications [
    #pub_.formatted
    #if "doi" in pub_ and pub_.doi != "" [
      #link("https://doi.org/" + pub_.doi)[DOI]
    ]
    #v(6pt)
  ]
]

// ..... Links .....
#if verified_links.len() > 0 [
  == Links
  #for lnk in verified_links [
    #link(lnk)[#lnk]
    #linebreak()
  ]
]
