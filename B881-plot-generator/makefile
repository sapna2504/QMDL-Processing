.PHONY: plot_all_qmdl

DIR ?= ../data

all:
	make plot_all_qmdl

plot_all_qmdl:
	@if [ -z "$(DIR)" ]; then \
		echo "Error: Please specify DIR (e.g., make plot_qmdl DIR=../loggers/scheduled_captures_ground)"; \
		exit 1; \
	fi
	@echo "Searching for subdirectories containing .qmdl files in $(DIR)..."
	@subdirs=$$(find "$(DIR)" -mindepth 1 -type f -name "*.qmdl" -exec dirname {} + 2>/dev/null | sort -u); \
	if [ -z "$$subdirs" ]; then \
		echo "No .qmdl files found in subdirectories of $(DIR)"; \
		exit 0; \
	fi; \
	for dir in $$subdirs; do \
		echo ""; \
		echo "=================================================="; \
		echo "Processing .qmdl files in: $$dir"; \
		echo "=================================================="; \
		qmdl_files=$$(ls "$$dir"/*.qmdl 2>/dev/null); \
		if [ -n "$$qmdl_files" ]; then \
			if [ ! -f "$$dir/qmdl-to-scat.txt" ]; then \
				echo "Decoding QMDL logs with scat..."; \
				scat -t qc -d $$qmdl_files > "$$dir/qmdl-to-scat.txt"; \
			fi; \
			if [ ! -f "$$dir/payloads.txt" ]; then \
				echo "Extracting diagnostic payload bytes..."; \
 				python3 $(MAKEFILE_DIR)qmdl_to_codes.py "$$dir/qmdl-to-scat.txt" "$$dir/payloads.txt"; \
			fi; \
			echo "Creating metrics csv..."; \
			python3 dump_readable_logs.py $$dir/payloads.txt; \
		fi; \
	done
