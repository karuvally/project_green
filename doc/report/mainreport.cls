%    Copyright (C) 2012  Govt. Engineering College, Thrissur
%
%	Author : Jain Basil Aliyas <jainbasil@gmail.com>
%		 Anoop Toffy <anoop.toffy90@gmail.com>
%
%    This program is free software: you can redistribute it and/or modify
%    it under the terms of the GNU General Public License as published by
%    the Free Software Foundation, either version 3 of the License, or
%    (at your option) any later version.
%
%    This program is distributed in the hope that it will be useful,
%    but WITHOUT ANY WARRANTY; without even the implied warranty of
%    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
%    GNU General Public License for more details.
%
%    You should have received a copy of the GNU General Public License
%    along with this program.  If not, see <http://www.gnu.org/licenses/>.

\ProvidesClass{mainreport}[]

\DeclareOption*{\PassOptionsToClass{\CurrentOption}{report}}
\ProcessOptions

\LoadClass[12pt,oneside]{report}

\RequirePackage{graphicx}

% The list of packages needed for creating an advanced report class.

\RequirePackage{fancyhdr}
\RequirePackage{amsmath}
\RequirePackage{geometry}
\RequirePackage{setspace}

% Macro for List of Symbols
\def\listofsymbols{\input{symbols} \clearpage}
\def\addsymbol #1: #2#3{$#1$ \> \parbox{5in}{#2 \dotfill \pageref{#3}}\\}
\def\newsymbol#1{\label{#1}} 

\pagenumbering{roman}

\setcounter{secnumdepth}{5}
\setcounter{tocdepth}{5}


\fancypagestyle{plain}{
\fancyhf{}
%\lhead{section \bfseries \thesection}
\chead{Mini Project, 2018}
\cfoot{Department of Computer Applications\\ \thepage }
\renewcommand{\headrulewidth}{0.5pt}
\renewcommand{\footrulewidth}{0.5pt}
}

\pagestyle{fancy}
%\lhead{eries \thesection}
\rhead{}
\fancyfoot{}
\lfoot{Department of Computer Applications}
\rfoot{\thepage}

% for setting up alternative directory paths to graphics files,
% remember to comment in "graphics" package
%
\graphicspath{{./eps/}{./tiff/}{./jpg/}{./fig/}{./dia/}{./gnuplot/}{./png/}}

\renewcommand{\headrulewidth}{0.5pt}
\renewcommand{\footrulewidth}{0.5pt}
\fancyhfoffset{10pt}
%------------
\usepackage{geometry}
\geometry{verbose,a4paper,tmargin=25.4mm,bmargin=31.75mm,lmargin=38.1mm,rmargin=31.75mm}

%To generate list of abbreviations
\usepackage{nomencl}
\makenomenclature

% setup of titlepage
%
\def\maketitle{%
\begin{titlepage}
\thispagestyle{empty}
\vspace*{0.7cm}
{\centering     
\huge
{\rm\bf REAL TIME TRAFFIC CONGESTION ANALYZER FOR ROAD SAFETY}\\
%Title must be in capital letters
%Adjust space here if the title goes to more than one line
\vspace{1cm}
\begin{figure}[ht] 
{\centering {\includegraphics[scale=.5]{2.jpg}}\par}
\end{figure}
\vspace{1cm}
\bf \Large{Mini Project 2018}\\
\vspace{1cm}
\tt
Done By \\
\vspace{.5cm}
\rm
{\normalsize \bf {ELISA SANTHOSH}}\\
{\normalsize \bf {JABIR ALI V}}\\
%{\normalsize \bf {student-name}}\\
%{\normalsize \bf {student-name}}\\
\vspace{1cm}
{\tt{Guided By}} \\
\vspace{.5cm}
 \hspace{.05cm} 
 {\normalsize \bf {Prof.Sini S Raj}}\\
 {\normalsize \bf {Assisstant Professor}}\\
\vspace{2cm}
{\bf Department of Computer Applications \\ 
College of Engineering\\
Trivandrum-695016}\\
} 
\pagebreak
\end{titlepage}
}



