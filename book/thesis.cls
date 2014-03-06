%% (c) Emmanuela Orsini 2007
%% (c) Michele Orru`    2013

\NeedsTeXFormat{LaTeX2e}[1995/12/01]
\ProvidesClass{thesis}

\RequirePackage{amsmath}
\RequirePackage{amssymb}
\RequirePackage{amsthm}
\RequirePackage{fancyhdr}


%%\bibliographystyle{amsalpha}

\newcommand\@ptsize{}
\newif\if@restonecol
\newif\if@titlepage
\@titlepagetrue
\newif\if@openright
\newif\if@mainmatter \@mainmattertrue
\if@compatibility\else
\DeclareOption{a4paper}
   {\setlength\paperheight {297mm}%
    \setlength\paperwidth  {210mm}}
\DeclareOption{a5paper}
   {\setlength\paperheight {210mm}%
    \setlength\paperwidth  {148mm}}
\DeclareOption{b5paper}
   {\setlength\paperheight {250mm}%
    \setlength\paperwidth  {176mm}}
\DeclareOption{letterpaper}
   {\setlength\paperheight {11in}%
    \setlength\paperwidth  {8.5in}}
\DeclareOption{legalpaper}
   {\setlength\paperheight {14in}%
    \setlength\paperwidth  {8.5in}}
\DeclareOption{executivepaper}
   {\setlength\paperheight {10.5in}%
    \setlength\paperwidth  {7.25in}}
\DeclareOption{landscape}
   {\setlength\@tempdima   {\paperheight}%
    \setlength\paperheight {\paperwidth}%
    \setlength\paperwidth  {\@tempdima}}
\fi
\if@compatibility
  \renewcommand\@ptsize{0}
\else
\DeclareOption{10pt}{\renewcommand\@ptsize{0}}
\fi
\DeclareOption{11pt}{\renewcommand\@ptsize{1}}
\DeclareOption{12pt}{\renewcommand\@ptsize{2}}
\if@compatibility\else
\DeclareOption{oneside}{\@twosidefalse \@mparswitchfalse}
\fi
\DeclareOption{twoside}{\@twosidetrue  \@mparswitchtrue}
\DeclareOption{draft}{\setlength\overfullrule{5pt}}
\if@compatibility\else
\DeclareOption{final}{\setlength\overfullrule{0pt}}
\fi
\DeclareOption{titlepage}{\@titlepagetrue}
\if@compatibility\else
\DeclareOption{notitlepage}{\@titlepagefalse}
\fi
\if@compatibility
\@openrighttrue
\else
\DeclareOption{openright}{\@openrighttrue}
\DeclareOption{openany}{\@openrightfalse}
\fi
\if@compatibility\else
\DeclareOption{onecolumn}{\@twocolumnfalse}
\fi
\DeclareOption{twocolumn}{\@twocolumntrue}
\DeclareOption{leqno}{\input{leqno.clo}}
\DeclareOption{fleqn}{\input{fleqn.clo}}
\DeclareOption{openbib}{%
  \AtEndOfPackage{%
   \renewcommand\@openbib@code{%
      \advance\leftmargin\bibindent
      \itemindent -\bibindent
      \listparindent \itemindent
      \parsep \z@
      }%
   \renewcommand\newblock{\par}}%
}
\ExecuteOptions{letterpaper,10pt,twoside,onecolumn,final,openright}
\ProcessOptions
\input{bk1\@ptsize.clo}
\setlength\lineskip{1\p@}
\setlength\normallineskip{1\p@}
\renewcommand\baselinestretch{}
\setlength\parskip{0\p@ \@plus \p@}
\@lowpenalty   51
\@medpenalty  151
\@highpenalty 301
\setcounter{topnumber}{2}
\renewcommand\topfraction{.7}
\setcounter{bottomnumber}{1}
\renewcommand\bottomfraction{.3}
\setcounter{totalnumber}{3}
\renewcommand\textfraction{.2}
\renewcommand\floatpagefraction{.5}
\setcounter{dbltopnumber}{2}
\renewcommand\dbltopfraction{.7}
\renewcommand\dblfloatpagefraction{.5}


\long\def\comment#1{}

\oddsidemargin 0.5in \evensidemargin 0in \marginparwidth 20pt
\marginparsep 8pt \topmargin 0pt \headsep .3in
%\textheight 8.1in
\textheight 9in
\textwidth 6in

% Disallow page breaks at hyphens (this will give some underfull vbox's,
% so an alternative is to use \brokenpenalty=100 and manually search
% for and fix such page breaks)
\brokenpenalty=10000

% Use 1.37 times the normal baseline-to-baseline skip
\renewcommand{\baselinestretch}{1.17}



% Redefine the macro used for footnotes to use single spacing
\long\def\@footnotetext#1{\insert\footins{\def\baselinestretch{1}\footnotesize
    \interlinepenalty\interfootnotelinepenalty
    \splittopskip\footnotesep
    \splitmaxdepth \dp\strutbox \floatingpenalty \@MM
    \hsize\columnwidth \@parboxrestore
   \edef\@currentlabel{\csname p@footnote\endcsname\@thefnmark}\@makefntext
    {\rule{\z@}{\footnotesep}\ignorespaces
      #1\strut}}}

\def\Logo#1{\gdef\@Logo{#1}}

\def\university#1{\gdef\@university{#1}}
\def\subtitle#1{\gdef\@subtitle{#1}}
\def\address#1{\gdef\@address{#1}}
\def\dept#1{\gdef\@dept{#1}}
\def\phdtitle#1{\gdef\@phdtitle{#1}}
\def\faculty#1{\gdef\@faculty{#1}}
\def\dedica#1{\gdef\@dedica{#1}}


\def\accademico#1{\gdef\@accademico{#1}}
\def\supervisor#1{\gdef\@supervisor{#1}}
\def\superviser#1{\gdef\@supervisor{#1}}
\def\firstreader#1{\gdef\@firstreader{#1}}
\def\secondreader#1{\gdef\@secondreader{#1}}
\def\thirdreader#1{\gdef\@thirdreader{#1}\third@readertrue}
\def\fourthreader#1{\gdef\@fourthreader{#1}\fourth@readertrue}
\def\fifthreader#1{\gdef\@fifthreader{#1}\fifth@readertrue}
\def\examiner#1{\gdef\@examiner{#1}}
\def\twosupervisors{\two@supervisorstrue}
\def\submitdate#1{\gdef\@submitdate{#1}}
\def\copyrightyear#1{\gdef\@copyrightyear{#1}} % \author, \title in report
\def\degree#1{\gdef\@degree{#1}}
\def\degreeinitial#1{\gdef\@degreeinitial{#1}}
\def\mastersc{\degree{Master of Science}\degreeinitial{M.Sc.}}
\mastersc % default degree
\def\phd{\degree{Doctor of Philosophy}\degreeinitial{Ph.D.}\ph@dtrue}
\def\ma{\degree{Master of Arts}\degreeinitial{M.A.}}
\def\@title{}
\def\@subtitle{\subtitle}
\def\@author{}

%% METADATA
\def\@university{\university}
\def\@faculty{\faculty}
\def\@Logo{\Logo}
\def\@phdtitle{\phdtitle}
\def\@dedica{\dedica}
\def\@address{Halifax, Nova Scotia}
\def\@dept{Dipartimento di Sociologia}


\def\@supervisor{}\def\@firstreader{}\def\@secondreader{}
\def\@thirdreader{}\def\@fourthreader{}\def\@fifthreader{}
\def\@examiner{}
\def\@submitdate{\ifcase\the\month\or
  January\or February\or March\or April\or May\or June\or
  July\or August\or September\or October\or November\or December\fi
  \space \number\the\year}
\def\@copyrightyear{\number\the\year}
\def\@accademico{}


\def\convocation#1#2{\gdef\@convocationmonth{#1}\gdef\@convocationyear{#2}}
\def\@convwarn{\typeout{Warning!  Convocation date may be incorrect!}}
\ifnum\month<5
   \def\@convocationmonth{May}
   \def\@convocationyear{\number\the\year\@convwarn}
\else\ifnum\month<10
   \def\@convocationmonth{October}
   \def\@convocationyear{\number\the\year\@convwarn}
\else
   \def\@convocationmonth{February}
   \@tempcnta=\year  \advance\@tempcnta by 1
   \def\@convocationyear{\number\the\@tempcnta\@convwarn}
\fi\fi

\def\dedicate#1{\dedic@tiontrue\gdef\dedication@text{#1}}


\def\nobib{\print@bibfalse}
\def\nofront{\front@pagesfalse\permissionfalse\figurespagefalse\tablespagefalse}

% New if constructs:    Default conditions:
\newif\ifpermission     \permissiontrue
\newif\iftablespage     \tablespagetrue
\newif\iffront@pages    \front@pagestrue
\newif\ifthird@reader   \third@readerfalse
\newif\iffourth@reader  \fourth@readerfalse
\newif\iffifth@reader   \fifth@readerfalse
\newif\ifph@d           \ph@dfalse
\newif\iftwo@supervisors \two@supervisorsfalse
\newif\ifdraft@mode     \draft@modefalse
\newif\ifprint@bib      \print@bibtrue
\newif\ifdedic@tion     \dedic@tionfalse

\def\no@breaks#1{{\def\\{ \ignorespaces}#1}}    % disallow explicit line breaks



\def\signature#1#2{\parbox[b]{1in}{\smash{#1}\vskip12pt}
\hfill \parbox[t]{3in}{\shortstack{\vrule width 3in height 0.4pt\\\small#2}}}

%% FRONTESPIZIO
\def\frontespizio{%
    \pagestyle{empty}%
    \begin{quotation}
    \begin{center}
        \expandafter{\large{\@university}} \\
        \vskip0.3in plus 1fill minus 0.1in
        \expandafter{\@faculty}\\
        \vskip0.1in plus 1fill minus 0.1in
         \expandafter{\@dept}\\
         \vskip0.2in plus 1fill minus 0.1in
         \begin{figure}[h!]
          \centering
         \includegraphics[width=3.5cm]{\@Logo}
         \end{figure}
    \ifph@d
       \expandafter{\@phdtitle} \\
    \fi
    %\end{center}



    \vskip 0.80in plus 0.4in minus 0.1in
    \hyphenpenalty=10000
    %\parindent=36pt
     %``{\bf \no@breaks{\large{\@title}}}''
        {\textbf \no@breaks{\Large{\@title}}}
        \\ \vspace{2 mm}
        \no@breaks{\textit{\small{\@subtitle}}}
    \end{center}

   \begin{center}
   \vskip0.2in plus 1fill minus 0.1in
   \expandafter{\large{\@author}}\\
   \end{center}
    % \vskip0.2in plus 1fill minus 0.1in
    % \begin{flushright}
    % Dated: \underbar{\ \@submitdate\ }
    % \end{flushright}
    % \vskip 0.5in plus 0.4in minus 0.1in    % se il titolo sta in una riga \vskip 0.8in plus...

    \iffourth@reader
        \def\sigskip{\vskip0.15in plus 0.2in minus 0.1in}
        \def\beginskip{\vskip0.3875in plus 0.2in minus 0.1in}
    \else
        \def\sigskip{\vskip0.3in plus 0.1in}
        \def\beginskip{\vskip0.5875in plus 0.1in}
    \fi

    \ifph@d
        \beginskip
        \iftwo@supervisors
          \sigskip {Supervisors: } {\hspace{1.42cm} \@supervisor}

          \hspace{4.15cm}{\@firstreader} \\   % senza spazio sopra 2.6
          \sigskip {Head of PhD School: } {\@secondreader} \\
          %\sigskip \signature{Examining Committee:}{\@secondreader} \\
        \else
           \sigskip {Supervisor: } {\hspace{1.6cm} \@supervisor}
           \sigskip
           \sigskip {Head of PhD School: } {\@secondreader} \\
        \fi
    \else % not Ph.D. degree:
        \beginskip
        \iftwo@supervisors
          \sigskip \begin{tabular}{l@{\hskip 2cm} l}
            Relatore: & {\@supervisor} \\ \\ \\
            Correlatore: & {\@firstreader} \\ \\
            Controrelatore: & {\@secondreader}
          \end{tabular}
        \else
          \sigskip \begin{tabular}{l@{\hskip 2cm} l}
            Relatore: & {\@supervisor} \\ \\ \\
            Controrelatore: & {\@secondreader}
          \end{tabular}
        \fi
     \fi

        \ifthird@reader
          \sigskip \signature{}{\@thirdreader} \\
        \fi

        \iffourth@reader
          \sigskip \signature{}{\@fourthreader} \\
        \fi

        \iffifth@reader
          \sigskip \signature{}{\@fifthreader} \\
        \fi
    \end{quotation}

   %\ifph@d
    \vskip 1.6in plus 0.4in minus 0.1in
   %\else % not Ph.D. degree:
     %\iftwo@supervisors
     % \vskip 1in plus 0.1in minus 0.6in
     %\else
     % \vskip 1.6in plus 0.4in minus 0.1in
     %\fi
   %\fi
    \begin{center}
    %\@submitdate \\
    \@accademico
    \end{center}
    \vfill }

%% PAGINE DELLE FIRME
\def\signaturepage{%
    \pagestyle{empty}%
    \begin{quotation}
    \begin{center}
       \expandafter{\large{\@university}}
        \vskip0.3in plus 1fill minus 0.1in
        \expandafter{\@faculty}
        \vskip0.1in plus 1fill minus 0.1in
         \expandafter{\@dept}\\
        \vskip0.1in plus 1fill minus 0.1in
         \begin{figure}[h!]
          \centering
         \includegraphics[width=3cm]{\@Logo}
         \end{figure}
       \ifph@d
       \expandafter{\@phdtitle}\\
       \else
       \vskip0.1in
       \fi

    %\end{center}
   \ifph@d
    \vskip 0.60in plus 0.4in minus 0.1in
    \hyphenpenalty=10000
   \else % not Ph.D. degree:
     \iftwo@supervisors
      \vskip 0.00162in plus 0.4in minus 0.1in
      \hyphenpenalty=10000
     \else
      \vskip 0.60in plus 0.4in minus 0.1in
      \hyphenpenalty=10000
     \fi
   \fi

    %\vskip 0.60in plus 0.4in minus 0.1in
    %\hyphenpenalty=10000
    %\parindent=36pt
     %``{\bf \no@breaks{\large{\@title}}}''
     {\textbf \no@breaks{\Large{\@title}}}
     \\ \vspace{2 mm}
     \no@breaks{\textit{\small{\@subtitle}}}
    \end{center}

   % \begin{center}
   % \expandafter{\large{\@author}}\\
   % \end{center}
    % \vskip0.2in plus 1fill minus 0.1in
    % \begin{flushright}
    % Dated: \underbar{\ \@submitdate\ }
    % \end{flushright}
    \vskip 0.5in plus 0.4in minus 0.1in %se il titolo sta in una riga \vskip 0.7in plus...

    \iffourth@reader
        \def\sigskip{\vskip0.15in plus 0.2in minus 0.1in}
        \def\beginskip{\vskip0.3875in plus 0.2in minus 0.1in}
    \else
        \def\sigskip{\vskip0.30in plus 0.1in}
        \def\beginskip{\vskip0.5875in plus 0.1in}
    \fi

    \ifph@d          % tesi di dottorato
        \beginskip
         \sigskip \signature{\@degreeinitial Thesis of:}  {\@author}\\
        \iftwo@supervisors
          \sigskip \signature{Supervisors:}{\@supervisor} \\
          \sigskip \signature{}{\@firstreader} \\
          \sigskip \signature{Head of PhD School:}{\@secondreader} \\
          %\sigskip \signature{Examining Committee:}{\@secondreader} \\
        \else
          \sigskip \signature{Supervisors:}{\@supervisor} \\
          \sigskip
          \sigskip \signature{Head of PhD School:}{\@secondreader} \\
        \fi
    \else % not Ph.D. degree:
        \beginskip
        \sigskip
        \sigskip \signature{Tesi di:}  {\@author}\\
        \sigskip
        \iftwo@supervisors
          \sigskip \signature{Relatori:}{\@supervisor} \\
          \sigskip \signature{}{\@firstreader} \\
          \sigskip \signature{Controrelatore:}{\@secondreader} \\
        \else
          \sigskip \signature{Relatore:}{\@supervisor} \\
          \sigskip \signature{Controrelatore:}{\@secondreader} \\
        \fi
     \fi

        \ifthird@reader
          \sigskip \signature{}{\@thirdreader} \\
        \fi

        \iffourth@reader
          \sigskip \signature{}{\@fourthreader} \\
        \fi

        \iffifth@reader
          \sigskip \signature{}{\@fifthreader} \\
        \fi
    \end{quotation}


    \vskip 1.1in plus 0.4in minus 0.1in
    \begin{center}
    %\@submitdate \\
    \@accademico
    \end{center}
    \vfill
    %\newpage\setcounter{page}{3}
    }


%% PAGINA DELLA DEDICA
\def\dedicapage{%
\pagestyle{empty}
\begin{center}\em\null\vskip1in
        \@dedica
        \vfill
\end{center}
}


\def\beforepreface{
\typeout{Manu}
\typeout{Errori colpa di Manu. I'm sorry!!!}
    \pagenumbering{roman}
    \pagestyle{plain}
    \titlep
    \iffront@pages\signaturepage\else\addtocounter{page}{1}\fi
    \ifpermission\permissionpage\else\addtocounter{page}{1}\fi
    \iffront@pages\ifdedic@tion
        \newpage\begin{center}\Large\em\null\vskip1in
        \dedication@text
        \vfill\end{center}
    \fi\fi
    \iffront@pages\tableofcontents\else\addtocounter{page}{1}\fi
    }

\def\nonumchapter#1{%
    \chapter*{#1}
    \addcontentsline{toc}{chapter}{#1}}


\def\prefacesection#1{%
    \chapter*{#1}
    \addcontentsline{toc}{chapter}{#1}}

\newenvironment{dedication}{\newpage\begin{center}\Large\em\null\vskip1in}%
{\vfill\end{center}}


\def\afterpreface{\newpage
    \pagenumbering{arabic}
    \typeout{Manuthesis preface pages completed.}
    %\properpagestyle
    }

% Start out normal
%\properpagestyle



% some fancy settings.
\let\fancy@def\gdef

\def\lhead{\@ifnextchar[{\@xlhead}{\@ylhead}}
\def\@xlhead[#1]#2{\fancy@def\@elhead{#1}\fancy@def\@olhead{#2}}
\def\@ylhead#1{\fancy@def\@elhead{#1}\fancy@def\@olhead{#1}}

\def\chead{\@ifnextchar[{\@xchead}{\@ychead}}
\def\@xchead[#1]#2{\fancy@def\@echead{#1}\fancy@def\@ochead{#2}}
\def\@ychead#1{\fancy@def\@echead{#1}\fancy@def\@ochead{#1}}

\def\rhead{\@ifnextchar[{\@xrhead}{\@yrhead}}
\def\@xrhead[#1]#2{\fancy@def\@erhead{#1}\fancy@def\@orhead{#2}}
\def\@yrhead#1{\fancy@def\@erhead{#1}\fancy@def\@orhead{#1}}

\def\lfoot{\@ifnextchar[{\@xlfoot}{\@ylfoot}}
\def\@xlfoot[#1]#2{\fancy@def\@elfoot{#1}\fancy@def\@olfoot{#2}}
\def\@ylfoot#1{\fancy@def\@elfoot{#1}\fancy@def\@olfoot{#1}}

\def\cfoot{\@ifnextchar[{\@xcfoot}{\@ycfoot}}
\def\@xcfoot[#1]#2{\fancy@def\@ecfoot{#1}\fancy@def\@ocfoot{#2}}
\def\@ycfoot#1{\fancy@def\@ecfoot{#1}\fancy@def\@ocfoot{#1}}

\def\rfoot{\@ifnextchar[{\@xrfoot}{\@yrfoot}}
\def\@xrfoot[#1]#2{\fancy@def\@erfoot{#1}\fancy@def\@orfoot{#2}}
\def\@yrfoot#1{\fancy@def\@erfoot{#1}\fancy@def\@orfoot{#1}}


\newif\if@fancyplain \@fancyplainfalse
\def\fancyplain#1#2{\if@fancyplain#1\else#2\fi}



\def\fancy@reset{\restorecr
 \def\baselinestretch{1}%
 \def\nouppercase##1{{\let\uppercase\relax\let\MakeUppercase\relax##1}}%
 \ifx\undefined\@newbaseline% NFSS not present; 2.09 or 2e
   \ifx\@normalsize\undefined \normalsize
   \else \@normalsize \fi
 \else% NFSS (2.09) present
  \@newbaseline%
 \fi}



\def\@fancyhead#1#2#3#4#5{#1\hbox to\headwidth{\fancy@reset\vbox{\hbox
{\rlap{\parbox[b]{\headwidth}{\raggedright#2\strut}}\hfill
\parbox[b]{\headwidth}{\centering#3\strut}\hfill
\llap{\parbox[b]{\headwidth}{\raggedleft#4\strut}}}\headrule}}#5}

\def\@fancyfoot#1#2#3#4#5{#1\hbox to\headwidth{\fancy@reset\vbox{\footrule
\hbox{\rlap{\parbox[t]{\headwidth}{\raggedright#2\strut}}\hfill
\parbox[b]{\headwidth}{\centering#3\strut}\hfill
\llap{\parbox[b]{\headwidth}{\raggedleft#4\strut}}}}}#5}

\def\headrule{{\if@fancyplain\let\headrulewidth\plainheadrulewidth\fi
\hrule\@height\headrulewidth\@width\headwidth \vskip-\headrulewidth}}



\def\ps@fancyplain{\ps@fancy \let\ps@plain\ps@plain@fancy}
\def\ps@plain@fancy{\@fancyplaintrue\ps@@fancy}




\def\ps@@fancy{
    \ps@empty %
    \def\@mkboth{\protect\markboth}%
    \def\@oddhead{\@fancyhead\@lodd\@olhead\@ochead\@orhead\@rodd}%
    \def\@evenhead{\@fancyhead\@rodd\@elhead\@echead\@erhead\@lodd}%

    \def\@oddfoot{\@fancyfoot\@lodd\@olfoot\@ocfoot\@orfoot\@rodd}%
    \def\@evenfoot{\@fancyfoot\@rodd\@elfoot\@ocfoot\@erfoot\@lodd}%
    \def\chaptermark##1{
      \markboth {%
        \ifnum \c@secnumdepth >\m@ne
          \if@mainmatter
             \slshape{\@chapapp\ \thechapter.} \ %
          \fi
        \fi
        ##1}{}}%
    \def\sectionmark##1{%
      \markright {%
        \ifnum \c@secnumdepth >\z@
          \slshape{\thesection.} \ %
        \fi
        ##1}}
     }

\lhead[\fancyplain{}]{\fancyplain{}{{{\nouppercase\rightmark}}}}
\chead{}
\rhead[\fancyplain{}{{{\nouppercase\leftmark}}}]{\fancyplain{}}
\cfoot[\fancyplain{}]{{\fancyplain{}{\thepage} }}
\lfoot{}%
\rfoot{}%

\def\@lodd{\if@reversemargin\hss\else\relax\fi}
\def\@rodd{\if@reversemargin\relax\else\hss\fi}



\def\ps@copyright{\let\@mkboth\@gobbletwo

\def\today{\number\day\slash\ifcase\month\or
  I\or II\or III\or IV\or V\or VI\or
  VII\or VIII\or IX\or X\or XI\or XII\fi\slash\number\year}
  \def\@oddhead{}%

  \let\@evenhead\@oddhead
  \def\@oddfoot{\small\slshape
    \today
    \def\@tempa{0}
    \ifx\@volume\@tempa
    \@Logo
    \fi
   }%
  \let\@evenfoot\@oddfoot
  %\def\@evenfoot{\date}
  %\let\@evenfoot
  %\let\@oddfoot
}



\if@twoside
  \def\ps@headings{%
      \let\@oddfoot\@empty\let\@evenfoot\@empty
      \def\@evenhead{\thepage\hfil\slshape\leftmark}%
      \def\@oddhead{{\slshape\rightmark}\hfil\thepage}%
      \let\@mkboth\markboth
    \def\chaptermark##1{%
      \markboth {\MakeUppercase{%
        \ifnum \c@secnumdepth >\m@ne
          \if@mainmatter
            \@chapapp\ \thechapter. \ %
          \fi
        \fi
        ##1}}{}}%
    \def\sectionmark##1{%
      \markright {\MakeUppercase{%
        \ifnum \c@secnumdepth >\z@
          \thesection. \ %
        \fi
        ##1}}}}
\else
  \def\ps@headings{%
    \let\@oddfoot\@empty
    \def\@oddhead{{\slshape\rightmark}\hfil\thepage}%
    \let\@mkboth\markboth
    \def\chaptermark##1{%
      \markright {\MakeUppercase{%
        \ifnum \c@secnumdepth >\m@ne
          \if@mainmatter
            \@chapapp\ \thechapter. \ %
          \fi
        \fi
        ##1}}}}
\fi
\def\ps@myheadings{%
    %\def\@oddfoot{{\small{{\tt{CGC}}}}\hfil\thepage\hfil\ }
    \let\@evenfoot\@empty
    %\def\@cfoot{\thepage}
    \let\@evenhead\@empty
    \let\@oddhead\@empty
    \let\@mkboth\@gobbletwo
    %\let\chaptermark\@gobble
    %\let\sectionmark\@gobble
    }


  \if@titlepage
  \newcommand\maketitle{\begin{titlepage}%
  \let\footnotesize\small
  \let\footnoterule\relax
  \let \footnote \thanks
  \null\vfil
  \vskip 60\p@
  \begin{center}%
    {\LARGE \@title \par}%
    \vskip 3em%
    {\large
     \lineskip .75em%
      \begin{tabular}[t]{c}%
        \@author
      \end{tabular}\par}%
      \vskip 1.5em%
    {\large \@date \par}%       % Set date in \large size.
  \end{center}\par
  \@thanks
  \vfil\null
  \end{titlepage}%
  \setcounter{footnote}{0}%
  \global\let\thanks\relax
  \global\let\maketitle\relax
  \global\let\@thanks\@empty
  \global\let\@author\@empty
  \global\let\@date\@empty
  \global\let\@title\@empty
  \global\let\@subtitle\@empty
  \global\let\title\relax
  \global\let\subtitle\relax
  \global\let\author\relax
  \global\let\date\relax
  \global\let\and\relax
}
\else
\newcommand\maketitle{\par
  \begingroup
    \renewcommand\thefootnote{\@fnsymbol\c@footnote}%
    \def\@makefnmark{\rlap{\@textsuperscript{\normalfont\@thefnmark}}}%
    \long\def\@makefntext##1{\parindent 1em\noindent
            \hb@xt@1.8em{%
                \hss\@textsuperscript{\normalfont\@thefnmark}}##1}%
    \if@twocolumn
      \ifnum \col@number=\@ne
        \@maketitle
      \else
        \twocolumn[\@maketitle]%
      \fi
    \else
      \newpage
      \global\@topnum\z@   % Prevents figures from going at top of page.
      \@maketitle
    \fi
    \thispagestyle{plain}\@thanks
  \endgroup
  \setcounter{footnote}{0}%
  \global\let\thanks\relax
  \global\let\maketitle\relax
  \global\let\@maketitle\relax
  \global\let\@thanks\@empty
  \global\let\@author\@empty
  \global\let\@date\@empty
  \global\let\@title\@empty
  \global\let\@subtitle\@empty
  \global\let\title\relax
  \global\let\subtitle\relax
  \global\let\author\relax
  \global\let\date\relax
  \global\let\and\relax
}
\def\@maketitle{%
  \newpage
  \null
  \vskip 2em%
  \begin{center}%
  \let \footnote \thanks
    {\LARGE \@title \par}%
    \vskip 1.5em%
    {\large
      \lineskip .5em%
      \begin{tabular}[t]{c}%
        \@author
      \end{tabular}\par}%
    \vskip 1em%
    {\large \@date}%
  \end{center}%
  \par
  \vskip 1.5em}
\fi
%\newcommand*\chaptermark[1]{}
\setcounter{secnumdepth}{2}
\newcounter {part}
\newcounter {chapter}
\newcounter {section}[chapter]
\newcounter {subsection}[section]
\newcounter {subsubsection}[subsection]
\newcounter {paragraph}[subsubsection]
\newcounter {subparagraph}[paragraph]
\renewcommand \thepart {\@Roman\c@part}
\renewcommand \thechapter {\@arabic\c@chapter}
\renewcommand \thesection {\thechapter.\@arabic\c@section}
\renewcommand\thesubsection   {\thesection.\@arabic\c@subsection}
\renewcommand\thesubsubsection{\thesubsection .\@arabic\c@subsubsection}
\renewcommand\theparagraph    {\thesubsubsection.\@arabic\c@paragraph}
\renewcommand\thesubparagraph {\theparagraph.\@arabic\c@subparagraph}
\newcommand\@chapapp{\chaptername}
\newcommand\frontmatter{%
    \cleardoublepage
  \@mainmatterfalse
  \pagenumbering{roman}}
\newcommand\mainmatter{%
    \cleardoublepage
  \@mainmattertrue
  \pagenumbering{arabic}}
\newcommand\backmatter{%
  \if@openright
    \cleardoublepage
  \else
    \clearpage
  \fi
  \@mainmatterfalse}
\newcommand\part{%
  \if@openright
    \cleardoublepage
  \else
    \clearpage
  \fi
  \thispagestyle{plain}%
  \if@twocolumn
    \onecolumn
    \@tempswatrue
  \else
    \@tempswafalse
  \fi
  \null\vfil
  \secdef\@part\@spart}

\def\@part[#1]#2{%
    \ifnum \c@secnumdepth >-2\relax
      \refstepcounter{part}%
      \addcontentsline{toc}{part}{\thepart\hspace{1em}#1}%
    \else
      \addcontentsline{toc}{part}{#1}%
    \fi
    \markboth{}{}%
    {\centering
     \interlinepenalty \@M
     \normalfont
     \ifnum \c@secnumdepth >-2\relax
       \Large\bfseries \partname\nobreakspace\thepart
       \par
       \vskip 20\p@
     \fi
     \huge \bfseries #2\par}%
    \@endpart}
\def\@spart#1{%
    {\centering
     \interlinepenalty \@M
     \normalfont
     \Huge \bfseries #1\par}%
    \@endpart}
\def\@endpart{\vfil\newpage
              \if@twoside
               \if@openright
                \null
                \thispagestyle{empty}%
                \newpage
               \fi
              \fi
              \if@tempswa
                \twocolumn
              \fi}

%% CAPITOLO
\newcommand\chapter{\if@openright\cleardoublepage\else\clearpage\fi
                    \thispagestyle{myheadings}%
                    \global\@topnum\z@
                    \@afterindentfalse
                    \secdef\@chapter\@schapter}
\def\@chapter[#1]#2{\ifnum \c@secnumdepth >\m@ne
                       \if@mainmatter
                         \refstepcounter{chapter}%
                         \typeout{\@chapapp\space\thechapter.}%
                         \addcontentsline{toc}{chapter}%
                                   {\protect\numberline{\thechapter}#1}%
                       \else
                         \addcontentsline{toc}{chapter}{#1}%
                       \fi
                    \else
                      \addcontentsline{toc}{chapter}{#1}%
                    \fi
                    \chaptermark{#1}%
                    \addtocontents{lof}{\protect\addvspace{10\p@}}%
                    \addtocontents{lot}{\protect\addvspace{10\p@}}%
                    \if@twocolumn
                      \@topnewpage[\@makechapterhead{#2}]%
                    \else
                      \@makechapterhead{#2}%
                      \@afterheading
                    \fi}
\def\@makechapterhead#1{%
  \vspace*{40\p@}%
  {\parindent \z@ \raggedright \normalfont
    \ifnum \c@secnumdepth >\m@ne
      \if@mainmatter
        \Large\bfseries  \space \space  #1     %se vuoi mettere il numer scrivi \thechapter prima di \space
        \par\nobreak
        \vskip 40\p@
      \fi
    \fi
  }}
\def\@schapter#1{\if@twocolumn
                   \@topnewpage[\@makeschapterhead{#1}]%
                 \else
                   \@makeschapterhead{#1}%
                   \@afterheading
                 \fi}
\def\@makeschapterhead#1{%
  \vspace*{40\p@}%
  {\parindent \z@ \raggedright
    \normalfont
    \interlinepenalty\@M
    \Large \bfseries  #1\par\nobreak
    \vskip 40\p@
  }}

%% SEZIONE
\newcommand\section{\@startsection {section}{1}{\z@}%
                                   {-3.5ex \@plus -1ex \@minus -.2ex}%
                                   {2.3ex \@plus.2ex}%
                                   {\normalfont\large\bfseries}}
\newcommand\subsection{\@startsection{subsection}{2}{\z@}%
                                     {-3.25ex\@plus -1ex \@minus -.2ex}%
                                     {1.5ex \@plus .2ex}%
                                     {\normalfont\itshape}}
\newcommand\subsubsection{\@startsection{subsubsection}{3}{\z@}%
                                     {-3.25ex\@plus -1ex \@minus -.2ex}%
                                     {1.5ex \@plus .2ex}%
                                     {\normalfont\normalsize\bfseries}}
\newcommand\paragraph{\@startsection{paragraph}{4}{\z@}%
                                    {3.25ex \@plus1ex \@minus.2ex}%
                                    {-1em}%
                                    {\normalfont\normalsize\bfseries}}
\newcommand\subparagraph{\@startsection{subparagraph}{5}{\parindent}%
                                       {3.25ex \@plus1ex \@minus .2ex}%
                                       {-1em}%
                                      {\normalfont\normalsize\bfseries}}
\if@twocolumn
  \setlength\leftmargini  {2em}
\else
  \setlength\leftmargini  {2.5em}
\fi
\leftmargin  \leftmargini
\setlength\leftmarginii  {2.2em}
\setlength\leftmarginiii {1.87em}
\setlength\leftmarginiv  {1.7em}
\if@twocolumn
  \setlength\leftmarginv  {.5em}
  \setlength\leftmarginvi {.5em}
\else
  \setlength\leftmarginv  {1em}
  \setlength\leftmarginvi {1em}
\fi
\setlength  \labelsep  {.5em}
\setlength  \labelwidth{\leftmargini}
\addtolength\labelwidth{-\labelsep}
\@beginparpenalty -\@lowpenalty
\@endparpenalty   -\@lowpenalty
\@itempenalty     -\@lowpenalty
\renewcommand\theenumi{\@arabic\c@enumi}
\renewcommand\theenumii{\@alph\c@enumii}
\renewcommand\theenumiii{\@roman\c@enumiii}
\renewcommand\theenumiv{\@Alph\c@enumiv}
\newcommand\labelenumi{\theenumi.}
\newcommand\labelenumii{(\theenumii)}
\newcommand\labelenumiii{\theenumiii.}
\newcommand\labelenumiv{\theenumiv.}
\renewcommand\p@enumii{\theenumi}
\renewcommand\p@enumiii{\theenumi(\theenumii)}
\renewcommand\p@enumiv{\p@enumiii\theenumiii}
\newcommand\labelitemi{\textbullet}
\newcommand\labelitemii{\normalfont\bfseries \textendash}
\newcommand\labelitemiii{\textasteriskcentered}
\newcommand\labelitemiv{\textperiodcentered}
\newenvironment{description}
               {\list{}{\labelwidth\z@ \itemindent-\leftmargin
                        \let\makelabel\descriptionlabel}}
               {\endlist}
\newcommand*\descriptionlabel[1]{\hspace\labelsep
                                \normalfont\bfseries #1}
\newenvironment{verse}
               {\let\\\@centercr
                \list{}{\itemsep      \z@
                        \itemindent   -1.5em%
                        \listparindent\itemindent
                        \rightmargin  \leftmargin
                        \advance\leftmargin 1.5em}%
                \item\relax}
               {\endlist}
\newenvironment{quotation}
               {\list{}{\listparindent 1.5em%
                        \itemindent    \listparindent
                        \rightmargin   \leftmargin
                        \parsep        \z@ \@plus\p@}%
                \item\relax}
               {\endlist}
\newenvironment{quote}
               {\list{}{\rightmargin\leftmargin}%
                \item\relax}
               {\endlist}
\if@compatibility
\newenvironment{titlepage}
    {%
      \cleardoublepage
      \if@twocolumn
        \@restonecoltrue\onecolumn
      \else
        \@restonecolfalse\newpage
      \fi
      \thispagestyle{empty}%
      \setcounter{page}\z@
    }%
    {\if@restonecol\twocolumn \else \newpage \fi
    }
\else
\newenvironment{titlepage}
    {%
      \cleardoublepage
      \if@twocolumn
        \@restonecoltrue\onecolumn
      \else
        \@restonecolfalse\newpage
      \fi
      \thispagestyle{empty}%
      \setcounter{page}\@ne
    }%
    {\if@restonecol\twocolumn \else \newpage \fi
     \if@twoside\else
        \setcounter{page}\@ne
     \fi
    }
\fi
\newcommand\appendix{\par
  \setcounter{chapter}{0}%
  \setcounter{section}{0}%
  \gdef\@chapapp{\appendixname}%
  \gdef\thechapter{\@Alph\c@chapter}}
\setlength\arraycolsep{5\p@}
\setlength\tabcolsep{6\p@}
\setlength\arrayrulewidth{.4\p@}
\setlength\doublerulesep{2\p@}
\setlength\tabbingsep{\labelsep}
\skip\@mpfootins = \skip\footins
\setlength\fboxsep{3\p@}
\setlength\fboxrule{.4\p@}
\@addtoreset {equation}{chapter}
\renewcommand\theequation
  {\ifnum \c@chapter>\z@ \thechapter.\fi \@arabic\c@equation}
\newcounter{figure}[chapter]
\renewcommand \thefigure
     {\ifnum \c@chapter>\z@ \thechapter.\fi \@arabic\c@figure}
\def\fps@figure{tbp}
\def\ftype@figure{1}
\def\ext@figure{lof}
\def\fnum@figure{\figurename\nobreakspace\thefigure}
\newenvironment{figure}
               {\@float{figure}}
               {\end@float}
\newenvironment{figure*}
               {\@dblfloat{figure}}
               {\end@dblfloat}
\newcounter{table}[chapter]
\renewcommand \thetable
     {\ifnum \c@chapter>\z@ \thechapter.\fi \@arabic\c@table}
\def\fps@table{tbp}
\def\ftype@table{2}
\def\ext@table{lot}
\def\fnum@table{\tablename\nobreakspace\thetable}
\newenvironment{table}
               {\@float{table}}
               {\end@float}
\newenvironment{table*}
               {\@dblfloat{table}}
               {\end@dblfloat}
\newlength\abovecaptionskip
\newlength\belowcaptionskip
\setlength\abovecaptionskip{10\p@}
\setlength\belowcaptionskip{0\p@}
\long\def\@makecaption#1#2{%
  \vskip\abovecaptionskip
  \sbox\@tempboxa{#1: #2}%
  \ifdim \wd\@tempboxa >\hsize
    #1: #2\par
  \else
    \global \@minipagefalse
    \hb@xt@\hsize{\hfil\box\@tempboxa\hfil}%
  \fi
  \vskip\belowcaptionskip}
\DeclareOldFontCommand{\rm}{\normalfont\rmfamily}{\mathrm}
\DeclareOldFontCommand{\sf}{\normalfont\sffamily}{\mathsf}
\DeclareOldFontCommand{\tt}{\normalfont\ttfamily}{\mathtt}
\DeclareOldFontCommand{\bf}{\normalfont\bfseries}{\mathbf}
\DeclareOldFontCommand{\it}{\normalfont\itshape}{\mathit}
\DeclareOldFontCommand{\sl}{\normalfont\slshape}{\@nomath\sl}
\DeclareOldFontCommand{\sc}{\normalfont\scshape}{\@nomath\sc}
\DeclareRobustCommand*\cal{\@fontswitch\relax\mathcal}
\DeclareRobustCommand*\mit{\@fontswitch\relax\mathnormal}
\newcommand\@pnumwidth{1.55em}
\newcommand\@tocrmarg{2.55em}
\newcommand\@dotsep{4.5}
\setcounter{tocdepth}{2}
\newcommand\tableofcontents{%
    \if@twocolumn
      \@restonecoltrue\onecolumn
    \else
      \@restonecolfalse
    \fi
    \chapter*{\contentsname
        \@mkboth{%
           \MakeUppercase\contentsname}{\MakeUppercase\contentsname}}%
    \@starttoc{toc}%
    \if@restonecol\twocolumn\fi
    }
\newcommand*\l@part[2]{%
  \ifnum \c@tocdepth >-2\relax
    \addpenalty{-\@highpenalty}%
    \addvspace{2.25em \@plus\p@}%
    \setlength\@tempdima{3em}%
    \begingroup
      \parindent \z@ \rightskip \@pnumwidth
      \parfillskip -\@pnumwidth
      {\leavevmode
       \large \bfseries #1\hfil \hb@xt@\@pnumwidth{\hss #2}}\par
       \nobreak
         \global\@nobreaktrue
         \everypar{\global\@nobreakfalse\everypar{}}%
    \endgroup
  \fi}
\newcommand*\l@chapter[2]{%
  \ifnum \c@tocdepth >\m@ne
    \addpenalty{-\@highpenalty}%
    \vskip 1.0em \@plus\p@
    \setlength\@tempdima{1.5em}%
    \begingroup
      \parindent \z@ \rightskip \@pnumwidth
      \parfillskip -\@pnumwidth
      \leavevmode \bfseries
      \advance\leftskip\@tempdima
      \hskip -\leftskip
      #1\nobreak\hfil \nobreak\hb@xt@\@pnumwidth{\hss #2}\par
      \penalty\@highpenalty
    \endgroup
  \fi}
\newcommand*\l@section{\@dottedtocline{1}{1.5em}{2.3em}}
\newcommand*\l@subsection{\@dottedtocline{2}{3.8em}{3.2em}}
\newcommand*\l@subsubsection{\@dottedtocline{3}{7.0em}{4.1em}}
\newcommand*\l@paragraph{\@dottedtocline{4}{10em}{5em}}
\newcommand*\l@subparagraph{\@dottedtocline{5}{12em}{6em}}
\newcommand\listoffigures{%
    \if@twocolumn
      \@restonecoltrue\onecolumn
    \else
      \@restonecolfalse
    \fi
    \chapter*{\listfigurename}%
      \@mkboth{\MakeUppercase\listfigurename}%
              {\MakeUppercase\listfigurename}%
    \@starttoc{lof}%
    \if@restonecol\twocolumn\fi
    }
\newcommand*\l@figure{\@dottedtocline{1}{1.5em}{2.3em}}
\newcommand\listoftables{%
    \if@twocolumn
      \@restonecoltrue\onecolumn
    \else
      \@restonecolfalse
    \fi
    \chapter*{\listtablename}%
      \@mkboth{%
          \MakeUppercase\listtablename}%
         {\MakeUppercase\listtablename}%
    \@starttoc{lot}%
    \if@restonecol\twocolumn\fi
    }
\let\l@table\l@figure
\newdimen\bibindent
\setlength\bibindent{1.5em}
\newenvironment{thebibliography}[1]
     {\chapter*{\bibname}%
      \@mkboth{\MakeUppercase\bibname}{\MakeUppercase\bibname}%
      \list{\@biblabel{\@arabic\c@enumiv}}%
           {\settowidth\labelwidth{\@biblabel{#1}}%
            \leftmargin\labelwidth
            \advance\leftmargin\labelsep
            \@openbib@code
            \usecounter{enumiv}%
            \let\p@enumiv\@empty
            \renewcommand\theenumiv{\@arabic\c@enumiv}}%
      \sloppy
      \clubpenalty4000
      \@clubpenalty \clubpenalty
      \widowpenalty4000%
      \sfcode`\.\@m}
     {\def\@noitemerr
       {\@latex@warning{Empty `thebibliography' environment}}%
      \endlist}
\newcommand\newblock{\hskip .11em\@plus.33em\@minus.07em}
\let\@openbib@code\@empty
\newenvironment{theindex}
               {\if@twocolumn
                  \@restonecolfalse
                \else
                  \@restonecoltrue
                \fi
                \twocolumn[\@makeschapterhead{\indexname}]%
                \@mkboth{\MakeUppercase\indexname}%
                        {\MakeUppercase\indexname}%
                \thispagestyle{plain}\parindent\z@
                \parskip\z@ \@plus .3\p@\relax
                \columnseprule \z@
                \columnsep 35\p@
                \let\item\@idxitem}
               {\if@restonecol\onecolumn\else\clearpage\fi}
\newcommand\@idxitem{\par\hangindent 40\p@}
\newcommand\subitem{\@idxitem \hspace*{20\p@}}
\newcommand\subsubitem{\@idxitem \hspace*{30\p@}}
\newcommand\indexspace{\par \vskip 10\p@ \@plus5\p@ \@minus3\p@\relax}
\renewcommand\footnoterule{%
  \kern-3\p@
  \hrule\@width.4\columnwidth
  \kern2.6\p@}
\@addtoreset{footnote}{chapter}
\newcommand\@makefntext[1]{%
    \parindent 1em%
    \noindent
    \hb@xt@1.8em{\hss\@makefnmark}#1}


%% ENVIRONMENTS
 \theoremstyle{plain}
 \newtheorem{thm}{Theorem}[section]
 \newtheorem{theorem}[thm]{Theorem}
 \newtheorem{corollary}[thm]{Corollary}
 \newtheorem{lemma}[thm]{Lemma}
 \newtheorem{claim}[thm]{Claim}
 \newtheorem{axiom}[thm]{Axiom}
 \newtheorem{conjecture}[thm]{Conjecture}
 \newtheorem{fact}[thm]{Fact}
 \newtheorem{hypothesis}[thm]{Hypothesis}
 \newtheorem{assumption}[thm]{Assumption}
 \newtheorem{proposition}[thm]{Proposition}
 \newtheorem{criterion}[thm]{Criterion}
 \newtheorem{definition}[thm]{Definition}
 \newtheorem{algorithm}{Algorithm}
 \theoremstyle{definition}
 \newtheorem{example}[thm]{Example}
\theoremstyle{remark}
 \newtheorem{remark}[thm]{Remark}
 \newtheorem{problem}[thm]{Problem}
 \newtheorem{principle}[thm]{Principle}

%% Abbreviations
\newcommand{\NN}{{\mathbb N}}
\newcommand{\RR}{{\mathbb R}}
\newcommand{\ZZ}{{\mathbb Z}}
\newcommand{\QQ}{{\mathbb Q}}
\newcommand{\CC}{{\mathbb C}}
\newcommand{\FF}{{\mathbb F}}
\newcommand{\FFF}{\overline{{\mathbb F}}}
\newcommand{\KK}{{\mathbb K}}
\newcommand{\KKK}{\overline{{\mathbb K}}}
\newcommand{\GR}{Gr\"{o}bner}
\newcommand{\Gr}{Gr\"{o}bner}


\newcommand{\lp}{\mathrm{Lp}}
\newcommand{\tp}{\mathrm{Tp}}


\newfont{\gotico}{eufm10 scaled \magstep1}


%% roba da Mora

%\def\card{\mathop{\rm card}\nolimits}
%\def\mappa#1{\smash{\mathop{\longrightarrow}\limits^{#1}}}
%\def\squareforqed{\hbox{\rlap{$\sqcap$}$\sqcup$}}
%\def\qed{\quad
%\ifmmode\squareforqed\else{\squareforqed \medskip}\fi}
%\def\then{\Longrightarrow}
%\def\text#1{\rm #1}
%\def\emph#1{\em #1}
%\def\Lou{Loustaunau}
%%\def\lc{\mathop{\rm lc}\nolimits}
%\def\chart{\mathop{\rm char}\nolimits}
%\newcommand{\Gr}{Gr\"ob\-ner}

\newcommand\contentsname{Contents}
\newcommand\listfigurename{List of Figures}
\newcommand\listtablename{List of Tables}
\newcommand\bibname{Bibliography}
\newcommand\indexname{Index}
\newcommand\figurename{Figure}
\newcommand\tablename{Table}
\newcommand\partname{Part}
\newcommand\chaptername{Chapter}
\newcommand\appendixname{Appendix}
\def\today{\ifcase\month\or
  January\or February\or March\or April\or May\or June\or
  July\or August\or September\or October\or November\or December\fi
  \space\number\day, \number\year}
\setlength\columnsep{10\p@}
\setlength\columnseprule{0\p@}
\pagestyle{headings}
\pagenumbering{arabic}
\if@twoside
\else
  \raggedbottom
\fi
\if@twocolumn
  \twocolumn
  \sloppy
  \flushbottom
\else
  \onecolumn
\fi
\endinput
