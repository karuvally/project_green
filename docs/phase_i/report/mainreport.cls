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

% attempt to use Times New Roman
% \usepackage{fontspec}
% \setmainfont{Times New Roman}

% set linespacing
\linespread{1.25}

% The list of packages needed for creating an advanced report class.
\RequirePackage{graphicx}
\RequirePackage{fancyhdr}
\RequirePackage{amsmath}
\RequirePackage{geometry}
\RequirePackage{setspace}

% disable page numbers from appearing before contents
\pagenumbering{gobble}

% Macro for List of Symbols
\def\listofsymbols{\input{symbols} \clearpage}
\def\addsymbol #1: #2#3{$#1$ \> \parbox{5in}{#2 \dotfill \pageref{#3}}\\}
\def\newsymbol#1{\label{#1}} 

% the footer stuff
\newcommand{\changefont}{\fontsize{12}{12}\selectfont}
\fancypagestyle{plain}{
\fancyfoot[C]{\thepage \changefont}
\renewcommand{\headrulewidth}{0.5pt}
\renewcommand{\footrulewidth}{0.5pt}
}

% for setting up alternative directory paths to graphics files,
% remember to comment in "graphics" package
%
\graphicspath{{./eps/}{./tiff/}{./jpg/}{./fig/}{./dia/}{./gnuplot/}{./png/}}

\renewcommand{\headrulewidth}{0.5pt}
\renewcommand{\footrulewidth}{0.5pt}
\fancyhfoffset{10pt}
%------------
\usepackage{geometry}
\geometry{verbose,a4paper,tmargin=25mm,bmargin=25mm,lmargin=35mm,rmargin=25mm}

% To generate list of abbreviations
\usepackage{nomencl}
\makenomenclature

% set section size
\usepackage{sectsty}
\sectionfont{\fontsize{12}{15}\selectfont}
\subsectionfont{\fontsize{12}{15}\selectfont}
\subsubsectionfont{\fontsize{12}{15}\selectfont}

% set spacing between chapter title and text
\usepackage{titlesec}
\titleformat{\chapter}[display]
{\normalfont\huge\bfseries\centering}{\chaptertitlename\ \thechapter}{14pt}{\Huge}
\titlespacing*{\chapter}{14pt}{14pt}{14pt}

% setup of titlepage
\def\maketitle{%
\begin{titlepage}
\thispagestyle{empty}
\vspace*{0.7cm}
{\centering     

\huge
{\rm\bf NETDOG - CONFIGURATION MANAGEMENT AND MONITORING SYSTEM}\\

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
{\normalsize \bf {ASWIN BABU K}}\\
%{\normalsize \bf {student-name}}\\
%{\normalsize \bf {student-name}}\\

\vspace{1cm}
{\tt{Guided By}} \\

\vspace{.5cm}
\hspace{.05cm} 
{\normalsize \bf {Prof. Baby Syla L}}\\
{\normalsize \bf {Assistant Professor}}\\

\vspace{1cm}
{\bf Department of Computer Applications \\ 
College of Engineering\\
Trivandrum-695016}\\
} 

\pagebreak
\end{titlepage}
}
