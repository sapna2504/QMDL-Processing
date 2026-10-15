.PHONY: plot_qmdl plot_all_qmdl

DIR ?= plots

plot_qmdl: plot_all_qmdl

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
			echo "Decoding QMDL logs with scat..."; \
			scat -t qc -d $$qmdl_files > "$$dir/qmdl-to-scat.txt"; \
			echo "Extracting diagnostic payload bytes..."; \
			python3 $(MAKEFILE_DIR)qmdl_to_codes.py "$$dir/qmdl-to-scat.txt" "$$dir/payloads.txt"; \
			pcap_file=$$(ls "$$dir"/*.pcap 2>/dev/null | head -n 1); \
			if [ -f "$$pcap_file" ]; then \
				echo "Plotting B881 correlation graph against PCAP: $$pcap_file..."; \
				python3 $(MAKEFILE_DIR)b881_plotter.py "$$dir/payloads.txt" "$$pcap_file" "$$dir/b881_correlation_plot.png"; \
			else \
				echo "No .pcap file found in $$dir, skipping PCAP correlation plot."; \
			fi; \
			echo "Plotting box plot metrics..."; \
			python3 $(MAKEFILE_DIR)b881_box_plotter.py "$$dir/payloads.txt" "$$dir/b881_box_plot.png"; \
		fi; \
	done
