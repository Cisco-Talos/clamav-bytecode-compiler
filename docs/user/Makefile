all: clambc-api.pdf clambc-abridged-user.pdf clambc-full-user.pdf

pdf: clambc-api.pdf clambc-abridged-user.pdf clambc-full-user.pdf

full: clambc-full-user.pdf

abridged: clambc-api.pdf clambc-abridged-user.pdf

clambc-api.pdf: clean ../doxygen/latex/refman.pdf
	cd ../doxygen/latex; make
	cp ../doxygen/latex/refman.pdf clambc-api.pdf

clambc-abridged-user.pdf: clean clambc-abridged-user.tex
	pdflatex clambc-abridged-user
	pdflatex clambc-abridged-user

clambc-full-user.pdf: clean clambc-full-user.tex
	pdflatex clambc-full-user
	pdflatex clambc-full-user

clean: clnonpdf
	rm -f clambc-api.pdf clambc-abridged-user.pdf clambc-full-user.pdf

clnonpdf:
	rm -f *.ps *.dvi *.aux *.toc *.idx *.ind *.ilg *.log *.out *.brf *.blg *.bbl *.glo