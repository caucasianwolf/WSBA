TARGET ?= example.com
OUTDIR ?= reports/$(subst .,-,$(TARGET))
PYTHON ?= python3

run:
	$(PYTHON) src/wsba.py --target $(TARGET) --out $(OUTDIR)

pdf:
	$(PYTHON) src/render_pdf.py $(OUTDIR)/final_report.md $(OUTDIR)/final_report.pdf

all: run final pdf

final:
	cp $(OUTDIR)/report.md $(OUTDIR)/final_report.md
