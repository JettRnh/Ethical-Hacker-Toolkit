#!/bin/bash
# Log viewer script for Ethical Hacker Toolkit
# View and filter toolkit logs
# Author: Jet
# GitHub: https://github.com/JettRnh

echo "Ethical Hacker Toolkit - Log Viewer"
echo "=================================="
echo ""

LOG_FILE="logs/eht.log"

if [ ! -f "$LOG_FILE" ]; then
    echo "No log file found. Run some commands first to generate logs."
    exit 1
fi

echo "Log file: $LOG_FILE"
echo "File size: $(du -h "$LOG_FILE" | cut -f1)"
echo "Lines: $(wc -l < "$LOG_FILE")"
echo ""
echo "Options:"
echo "  1. Show last 20 lines"
echo "  2. Show last 50 lines"
echo "  3. Show all logs"
echo "  4. Filter by SUCCESS"
echo "  5. Filter by ERROR"
echo "  6. Filter by WARNING"
echo "  7. Search by keyword"
echo "  8. Exit"
echo ""

read -p "Select option [1-8]: " OPTION

case $OPTION in
    1)
        echo ""
        echo "Last 20 lines:"
        echo "==============="
        tail -20 "$LOG_FILE"
        ;;
    2)
        echo ""
        echo "Last 50 lines:"
        echo "==============="
        tail -50 "$LOG_FILE"
        ;;
    3)
        echo ""
        echo "All logs:"
        echo "========="
        cat "$LOG_FILE"
        ;;
    4)
        echo ""
        echo "Success logs:"
        echo "============="
        grep -i "success" "$LOG_FILE"
        ;;
    5)
        echo ""
        echo "Error logs:"
        echo "==========="
        grep -i "error" "$LOG_FILE"
        ;;
    6)
        echo ""
        echo "Warning logs:"
        echo "============="
        grep -i "warning" "$LOG_FILE"
        ;;
    7)
        read -p "Enter keyword: " KEYWORD
        echo ""
        echo "Search results for '$KEYWORD':"
        echo "==============================="
        grep -i "$KEYWORD" "$LOG_FILE"
        ;;
    8)
        echo "Exiting."
        exit 0
        ;;
    *)
        echo "Invalid option."
        exit 1
        ;;
esac
